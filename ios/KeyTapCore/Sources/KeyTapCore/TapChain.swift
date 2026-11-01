import Foundation

/// The tapped YubiKey, as one tap session sees it: its serial (read WITHOUT a PIN), its PIV side and its
/// FIDO2 side over the same connection. A software stand-in implements it for the soft phone and tests.
public protocol TappedKey: Sendable {
    /// The serial, read before any PIN is sent. nil on firmware without GET SERIAL.
    func serial() async throws -> UInt32?
    /// PIV VERIFY with the PIN (decryptions, the dry run). Called at most once per tap.
    func verifyPIV(pin: String) async throws
    /// The PIV key for unwrapping (valid after verifyPIV).
    func ageKey() async throws -> AgeKey
    /// An OpenSSH sk signature on the FIDO2 applet, PIN-verified. Throws CTAPError.noCredential when this key
    /// does not hold the credential.
    func sshSign(_ s: ApprovalRequest.SSHSign, pin: String) async throws -> CTAP2.Assertion
}

/// The bridge as a chain sees it: send an answer, wait for the request that continues a given one.
public protocol ChainLink: Sendable {
    func send(_ answer: ApprovalAnswer) async throws
    /// The next request of the chain (its `continues` is `after`), or nil when the computer ended the chain;
    /// `reason` says why.
    func next(after id: String, timeout: Duration) async throws -> (ApprovalRequest, Data)?
    func endReason() async -> String?
}

public enum TapError: Error, Equatable, LocalizedError {
    /// The tapped key is not the one the PIN was entered for. No PIN was sent to it.
    case otherKeyTapped(tapped: UInt32, tappedLabel: String, picked: UInt32, pickedLabel: String)
    /// The tapped key cannot answer anything in this chain.
    case notThisKey(String)
    /// The computer withdrew the request (answered elsewhere, the command ended, …).
    case withdrawn(String)
    case noFileKey(String)

    public var errorDescription: String? {
        switch self {
        case .otherKeyTapped(_, let t, _, let p):
            "This is \(t), but you entered the PIN for \(p). Nothing was sent to the key. Pick \(t) and enter its PIN, or tap \(p)."
        case .notThisKey(let why): why
        case .withdrawn(let why): "Withdrawn on the computer: \(why)."
        case .noFileKey(let why): why
        }
    }
}

/// What a finished tap did.
public enum TapOutcome: Equatable, Sendable {
    case decrypted(files: Int)
    case signed(flags: UInt8)
    case dryRun
}

/// Runs one chain inside one tap: the PIN only goes to the key it was entered for (checked by serial first),
/// at most one VERIFY, and requests for another key are answered "held" while the key stays connected.
public enum TapChain {
    public static func run(request first: ApprovalRequest, bytes firstBytes: Data, picked: UInt32?, pin: String,
                           key: TappedKey, link: ChainLink, signer: DeviceSigner,
                           holdTimeout: Duration = .seconds(20),
                           onRequest: @Sendable (ApprovalRequest, Data) async -> Void = { _, _ in }) async throws -> TapOutcome {
        let tapped = try await key.serial()
        if let picked, let tapped, picked != tapped {
            throw TapError.otherKeyTapped(tapped: tapped, tappedLabel: first.label(of: tapped),
                                          picked: picked, pickedLabel: first.label(of: picked))
        }
        var req = first, bytes = firstBytes
        var pivVerified = false
        func verifyOnce() async throws {
            if !pivVerified {
                try await key.verifyPIV(pin: pin)
                pivVerified = true
            }
        }
        while true {
            if req.isTest {
                if let tapped, let p = req.probe, p.serial != tapped {
                    throw TapError.notThisKey("The dry run is for \(req.label(of: p.serial)); this is \(req.label(of: tapped)).")
                }
                try await verifyOnce()
                let proof = try await Approver.probe(req, with: try await key.ageKey())
                try await link.send(try Approver.answerProbe(req, requestBytes: bytes, proof: proof, signer: signer))
                return .dryRun
            }
            if let ssh = req.ssh, req.isSSH {
                let mine = tapped == nil || ssh.keySerial == nil || ssh.keySerial == tapped
                if mine {
                    do {
                        let a = try await key.sshSign(ssh, pin: pin)
                        try await link.send(try Approver.answerSSH(req, requestBytes: bytes, assertion: a, signer: signer))
                        return .signed(flags: a.flags)
                    } catch CTAPError.noCredential {
                        // this key does not hold the credential: hold it for the next identity ssh tries
                    }
                }
            } else if !req.isUnknownKind {
                let forMe = tapped == nil || req.identities.contains { $0.serial == tapped }
                if forMe {
                    try await verifyOnce()
                    let results = try await Approver.unwrap(req, with: try await key.ageKey())
                    if results.contains(where: { $0.fileKey != nil }) {
                        try await link.send(try Approver.answer(req, requestBytes: bytes, results: results, signer: signer))
                        return .decrypted(files: results.filter { $0.fileKey != nil }.count)
                    }
                    if tapped != nil {
                        throw TapError.noFileKey(results.first?.error.map { "\(req.label(of: tapped!)) could not unwrap the file key (\($0))." }
                                                 ?? "\(req.label(of: tapped!)) could not unwrap the file key.")
                    }
                }
            } else {
                throw ApprovalError.unsupported
            }
            // Not for the tapped key: hold it and wait for the request that is.
            guard let tapped else { throw TapError.notThisKey("This YubiKey cannot answer this request.") }
            try await link.send(try Approver.held(req, requestBytes: bytes, serial: tapped, signer: signer))
            guard let (n, nb) = try await link.next(after: req.id, timeout: holdTimeout) else {
                let why = await link.endReason()
                if let why, why.contains("answered elsewhere") { throw TapError.withdrawn(why) }
                throw TapError.notThisKey(why.map { $0.prefix(1).uppercased() + $0.dropFirst() + "." }
                                          ?? "\(req.label(of: tapped)) is not one of the keys this request can use.")
            }
            req = n
            bytes = nb
            await onRequest(n, nb) // a wrong PIN from here on is retried on this request
        }
    }
}

public enum ApprovalError: Error, LocalizedError, Equatable {
    case nothingUnwrapped(String)
    case unsupported
    case sshNeedsYubiKey
    public var errorDescription: String? {
        switch self {
        case .nothingUnwrapped(let why): why
        case .unsupported: "This request needs a newer version of KeyTap. Update the app from the App Store."
        case .sshNeedsYubiKey: "SSH requests need a real YubiKey; the software test key handles decryptions only."
        }
    }
}

/// The real YubiKey over one ISO 7816 connection (NFC on the phone): PIV for the serial and decryptions,
/// FIDO2 for SSH. Selecting one applet deselects the other, so each side selects before use.
public actor YubiKeyTap: TappedKey {
    let t: PIVTransport
    private var pivSelected = false
    private var fidoToken: (rpId: String, token: Data, proto: PinProtocol)?
    private var age: YubiKeyAgeKey?

    public init(_ transport: PIVTransport) { self.t = transport }

    private func piv() async throws -> PIV {
        let p = PIV(t)
        if !pivSelected {
            try await p.select()
            pivSelected = true
        }
        return p
    }

    public func serial() async throws -> UInt32? {
        try await piv().serial()
    }

    public func verifyPIV(pin: String) async throws {
        try await piv().verify(pin: pin)
    }

    public func ageKey() async throws -> AgeKey {
        if let age { return age }
        let k = YubiKeyAgeKey(piv: try await piv())
        age = k
        return k
    }

    public func sshSign(_ s: ApprovalRequest.SSHSign, pin: String) async throws -> CTAP2.Assertion {
        guard let cred = Data(base64Raw: s.credentialID), let hash = Data(base64Raw: s.clientDataHash), hash.count == 32 else {
            throw CTAPError.malformed
        }
        let ctap = CTAP2(t)
        try await ctap.select()
        pivSelected = false
        let info = try await ctap.fido2Info()
        var token: (token: Data, proto: PinProtocol)?
        if !pin.isEmpty {
            guard info.options["clientPin"] == true else { throw CTAPError.pinNotSet }
            if let f = fidoToken, f.rpId == s.application {
                token = (f.token, f.proto)
            } else {
                let tk = try await ctap.pinToken(pin: pin, rpId: s.application, info: info)
                fidoToken = (s.application, tk.token, tk.proto)
                token = tk
            }
        } else if s.userVerification {
            throw CTAPError.pinRequired
        }
        return try await ctap.getAssertion(rpId: s.application, clientDataHash: hash, credentialID: cred,
                                           userPresence: s.userPresence, pinToken: token)
    }

    deinit {
        if var t = fidoToken?.token { t.resetBytes(in: 0..<t.count) }
    }
}

/// A software stand-in: a software age key and a software FIDO2 authenticator under a chosen serial.
public struct SoftwareTap: TappedKey {
    public let serialNumber: UInt32
    public let age: SoftwareAgeKey?
    public let fido: SoftFIDOAuthenticator?
    public let fidoPIN: String

    public init(serial: UInt32, age: SoftwareAgeKey?, fido: SoftFIDOAuthenticator?, fidoPIN: String = "123456") {
        self.serialNumber = serial
        self.age = age
        self.fido = fido
        self.fidoPIN = fidoPIN
    }

    public func serial() async throws -> UInt32? { serialNumber }
    public func verifyPIV(pin: String) async throws {}
    public func ageKey() async throws -> AgeKey {
        guard let age else { throw PIVError.slotEmpty }
        return age
    }
    public func sshSign(_ s: ApprovalRequest.SSHSign, pin: String) async throws -> CTAP2.Assertion {
        guard let fido else { throw CTAPError.noCredential }
        return try await SSHSigner.sign(s, pin: fidoPIN, transport: fido)
    }
}

/// The chain over a real bridge connection: polls for the continuation.
public struct BridgeChainLink: ChainLink {
    let client: BridgeClient
    let reason = ReasonBox()

    public init(client: BridgeClient) { self.client = client }

    public func send(_ answer: ApprovalAnswer) async throws { try await client.send(answer) }

    public func next(after id: String, timeout: Duration) async throws -> (ApprovalRequest, Data)? {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            switch try await client.poll() {
            case .pending(let r, let b) where r.continues == id:
                return (r, b)
            case .ended(_, let why):
                reason.set(why)
                return nil
            case .notListening:
                reason.set("the computer stopped waiting")
                return nil
            default:
                break
            }
            try await Task.sleep(for: .milliseconds(150))
        }
        return nil
    }

    public func endReason() async -> String? { reason.get() }
}

final class ReasonBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    func set(_ v: String) { lock.withLock { value = v } }
    func get() -> String? { lock.withLock { value } }
}
