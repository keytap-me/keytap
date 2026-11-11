// keytap-softphone — the phone's half of KeyTap on a Mac, with a SOFTWARE key in place of the
// YubiKey. For end-to-end tests of the bridge only: its key is a throwaway, never a recipient
// of anything real.
//
//   keytap-softphone keygen [--serial N]    create the throwaway key (as YubiKey N, default 1); print recipient + identity
//   keytap-softphone pair '<keytap://pair…>'
//   keytap-softphone approve [--decline] [--pick N]
//                                           wait for one request, answer it (the whole chain, in one "tap"), exit.
//                                           --pick N: enter the PIN for YubiKey N (a different serial is refused
//                                           before any PIN is sent, as on the phone)
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
    var serial: UInt32?
}

func flag(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
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
        var s = (try? load()) ?? State(ageKey: SoftwareAgeKey().rawRepresentation, signer: SoftwareSigner().rawRepresentation)
        if let n = flag("--serial").flatMap(UInt32.init) { s.serial = n }
        try save(s)
        let k = try SoftwareAgeKey(rawRepresentation: s.ageKey)
        print("recipient: \(k.recipient)")
        print("identity:  \(k.identity(serial: s.serial ?? SoftwareAgeKey.fakeSerial))")
    case "pair":
        guard args.count == 2, let link = PairingLink(args[1]) else { fail("usage: pair '<keytap://pair?…>'") }
        var s = try load()
        let signer = try SoftwareSigner(rawRepresentation: s.signer)
        let client = BridgeClient(host: link.host, pin: link.pin, token: nil)
        let (token, name, _) = try await client.pair(code: link.code, deviceName: "softphone", publicKey: signer.publicKeyX963)
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
        let serial = s.serial ?? SoftwareAgeKey.fakeSerial
        let tap = SoftwareTap(serial: serial, age: key, fido: s.fido.map { SoftFIDOAuthenticator(credential: $0, pin: "123456") })
        let link = BridgeChainLink(client: client)
        let deadline = Date().addingTimeInterval(60)
        while Date() < deadline {
            guard case .pending(let req, let bytes) = try await client.poll(), req.continues == nil else {
                try await Task.sleep(for: .milliseconds(300))
                continue
            }
            print("request \(req.code) from \(req.user)@\(req.host): \(req.command) [\(req.files.count) file(s)]")
            print("keys: \(req.offeredKeys.map { "\($0.label)=\($0.serial)" }.joined(separator: " ")) default \(req.defaultKey.map(String.init) ?? "-")")
            if let n = req.displayNote { print("note: \(n)") }
            if let ssh = req.ssh { print("ssh key: \(ssh.keyName ?? "(no name) " + (ssh.keyFingerprint ?? "-"))") }
            if args.contains("--decline") {
                try await client.send(try Approver.decline(req, requestBytes: bytes, signer: signer))
                print("declined")
                exit(0)
            }
            let picked = flag("--pick").flatMap(UInt32.init) ?? serial
            let current = CurrentRequest(req, bytes)
            do {
                let out = try await TapChain.run(request: req, bytes: bytes, picked: picked, pin: "123456", key: tap, link: link,
                                                 signer: signer) { next, nb in
                    current.set(next, nb)
                    print("continues: request \(next.code) (\(next.isSSH ? "ssh" : "\(next.files.count) file(s)"))")
                }
                switch out {
                case .decrypted(let n): print("answered: \(n) file(s) unwrapped by YubiKey \(serial)")
                case .signed(let f): print("signed ssh with YubiKey \(serial) (flags \(f))")
                case .dryRun: print("answered the dry run")
                }
            } catch let e as TapError {
                print("tap: \(e.localizedDescription)")
                // a person would re-pick and tap again; the soft phone gives up and declines, so the command ends
                let (r, b) = current.get()
                if case .otherKeyTapped = e { try? await client.send(try Approver.decline(r, requestBytes: b, signer: signer)) }
                exit(3)
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
        fail("usage: keytap-softphone keygen [--serial N] | pair <link> | approve [--decline] [--pick N] | fido-keygen <application> <key file>")
    }
} catch {
    fail("\(error.localizedDescription)")
}

final class CurrentRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var value: (ApprovalRequest, Data)
    init(_ r: ApprovalRequest, _ b: Data) { value = (r, b) }
    func set(_ r: ApprovalRequest, _ b: Data) { lock.withLock { value = (r, b) } }
    func get() -> (ApprovalRequest, Data) { lock.withLock { value } }
}
