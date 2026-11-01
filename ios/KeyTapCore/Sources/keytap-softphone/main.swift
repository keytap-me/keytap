// keytap-softphone — the phone's half of KeyTap on a Mac, with a SOFTWARE key in place of the
// YubiKey. For end-to-end tests of the bridge only: its key is a throwaway, never a recipient
// of anything real.
//
//   keytap-softphone keygen                 create the throwaway key; print recipient + identity
//   keytap-softphone pair '<keytap://pair…>'
//   keytap-softphone approve [--decline]    wait for one request, answer it, exit
//   keytap-softphone fido-keygen <application> <key file>
//                                           a throwaway FIDO2 credential (PIN 123456) + its OpenSSH key files
//                                           (<key file>, <key file>.pub), for ssh requests (keytap-sk)
//
// State: $KEYTAP_SOFTPHONE_DIR (default ~/.keytap-softphone).
import Foundation
import KeyTapCore

struct State: Codable {
    var ageKey: Data
    var signer: Data
    var host: String?
    var pin: Data?
    var token: String?
    var fido: SoftFIDOAuthenticator.Credential?
}

let dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["KEYTAP_SOFTPHONE_DIR"]
    ?? (NSHomeDirectory() + "/.keytap-softphone"))
let stateURL = dir.appending(path: "state.json")

func load() throws -> State {
    try JSONDecoder().decode(State.self, from: Data(contentsOf: stateURL))
}

func save(_ s: State) throws {
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    try JSONEncoder().encode(s).write(to: stateURL, options: .atomic)
}

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("softphone: \(msg)\n".utf8))
    exit(1)
}

let args = Array(CommandLine.arguments.dropFirst())
do {
    switch args.first {
    case "keygen":
        let s = (try? load()) ?? State(ageKey: SoftwareAgeKey().rawRepresentation, signer: SoftwareSigner().rawRepresentation)
        try save(s)
        let k = try SoftwareAgeKey(rawRepresentation: s.ageKey)
        print("recipient: \(k.recipient)")
        print("identity:  \(k.identity)")
    case "pair":
        guard args.count == 2, let link = PairingLink(args[1]) else { fail("usage: pair '<keytap://pair?…>'") }
        var s = try load()
        let signer = try SoftwareSigner(rawRepresentation: s.signer)
        let client = BridgeClient(host: link.host, pin: link.pin, token: nil)
        let key = try SoftwareAgeKey(rawRepresentation: s.ageKey)
        let reg = BridgeClient.RegisteredKey(serial: SoftwareAgeKey.fakeSerial, slot: SoftwareAgeKey.slot, recipient: key.recipientPoint)
        let (token, name, _) = try await client.pair(code: link.code, deviceName: "softphone", publicKey: signer.publicKeyX963,
                                                  yubikeys: [reg])
        s.host = link.host
        s.pin = link.pin
        s.token = token
        try save(s)
        print("paired with \(name) at \(link.host)")
    case "approve":
        let s = try load()
        guard let host = s.host, let pin = s.pin, let token = s.token else { fail("not paired") }
        let client = BridgeClient(host: host, pin: pin, token: token)
        let signer = try SoftwareSigner(rawRepresentation: s.signer)
        let key = try SoftwareAgeKey(rawRepresentation: s.ageKey)
        let deadline = Date().addingTimeInterval(60)
        while Date() < deadline {
            guard case .pending(let req, let bytes) = try await client.poll() else {
                try await Task.sleep(for: .milliseconds(300))
                continue
            }
            print("request \(req.code) from \(req.user)@\(req.host): \(req.command) [\(req.files.count) file(s)]")
            if let n = req.displayNote { print("note: \(n)") }
            if req.isSSH, let sign = req.ssh, !args.contains("--decline") {
                guard let cred = s.fido else { fail("ssh request, but no FIDO credential (fido-keygen)") }
                let key = SoftFIDOAuthenticator(credential: cred, pin: "123456")
                let a = try await SSHSigner.sign(sign, pin: "123456", transport: key)
                try await client.send(try Approver.answerSSH(req, requestBytes: bytes, assertion: a, signer: signer))
                print("signed ssh \(sign.purpose) as \(sign.login ?? "?") with \(sign.keyName ?? sign.keyFingerprint ?? "?") (flags \(a.flags)), server key \(sign.hostKeyFingerprint ?? "-")")
            } else if req.isTest {
                let proof = try await Approver.probe(req, with: key)
                try await client.send(try Approver.answerProbe(req, requestBytes: bytes, proof: proof, signer: signer))
                print("answered the dry run")
            } else if args.contains("--decline") {
                try await client.send(try Approver.decline(req, requestBytes: bytes, signer: signer))
                print("declined")
            } else {
                let results = try await Approver.unwrap(req, with: key)
                try await client.send(try Approver.answer(req, requestBytes: bytes, results: results, signer: signer))
                print("answered: \(results.filter { $0.fileKey != nil }.count)/\(results.count) unwrapped")
            }
            exit(0)
        }
        fail("no request within 60 s")
    case "fido-keygen":
        guard args.count == 3 else { fail("usage: fido-keygen <application, e.g. ssh:> <key file>") }
        var s = try load()
        let cred = SoftFIDOAuthenticator.Credential(rpId: args[1])
        let files = cred.opensshFiles(comment: "keytap-softphone")
        try Data(files.privateKey.utf8).write(to: URL(fileURLWithPath: args[2]))
        chmod(args[2], 0o600)
        try Data(files.publicKey.utf8).write(to: URL(fileURLWithPath: args[2] + ".pub"))
        s.fido = cred
        try save(s)
        print(files.publicKey, terminator: "")
    default:
        fail("usage: keytap-softphone keygen | pair <link> | approve [--decline] | fido-keygen <application> <key file>")
    }
} catch {
    fail("\(error.localizedDescription)")
}
