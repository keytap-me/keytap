import CommonCrypto
import CryptoKit
import Foundation

/// FIDO2 (CTAP 2.0 / 2.1) over ISO 7816 APDUs: the YubiKey's FIDO applet over NFC on the phone, or the software
/// authenticator in tests. KeyTap uses exactly one operation: getAssertion for an OpenSSH sk key, with user
/// verification by the PIN (clientPIN protocol 2, or 1 for older keys). The PIN goes only to the authenticator,
/// encrypted under a fresh key agreement, and is never stored.
public struct CTAP2: Sendable {
    public static let aid = Data([0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
    let t: PIVTransport

    public init(_ transport: PIVTransport) { self.t = transport }

    public enum Command: UInt8 { case getAssertion = 0x02, getInfo = 0x04, clientPIN = 0x06 }

    // MARK: transport

    func send(_ apdu: Data) async throws -> (Data, UInt16) {
        var (data, sw) = try await t.transmit(apdu)
        while true {
            if sw >> 8 == 0x61 { // more response bytes waiting
                let (more, next) = try await t.transmit(Data([0x00, 0xC0, 0x00, 0x00, UInt8(sw & 0xFF)]))
                data += more
                sw = next
            } else if sw == 0x9100 { // NFCCTAP keepalive: still processing, ask again
                try await Task.sleep(for: .milliseconds(100))
                (data, sw) = try await t.transmit(Data([0x80, 0x11, 0x00, 0x00]))
            } else {
                return (data, sw)
            }
        }
    }

    public func select() async throws {
        let (resp, sw) = try await send(Data([0x00, 0xA4, 0x04, 0x00, UInt8(Self.aid.count)]) + Self.aid + Data([0x00]))
        guard sw == 0x9000 else { throw CTAPError.noFIDOApplet }
        // CTAP 2.1 §11.3: a key that ALSO speaks U2F answers "U2F_V2" (every YubiKey 5 does), a FIDO2-only key
        // "FIDO_2_0". The answer says nothing about FIDO2 support — getInfo decides that (fido2Info).
        _ = resp
    }

    /// getInfo, failing as notFIDO2 when the key does not speak CTAP2 (a U2F-only key rejects the command).
    public func fido2Info() async throws -> Info {
        let info: Info
        do {
            info = try await self.info()
        } catch CTAPError.transport(sw: _), CTAPError.status(0x01) { // CTAP1_ERR_INVALID_COMMAND
            throw CTAPError.notFIDO2
        }
        guard info.versions.contains(where: { $0.hasPrefix("FIDO_2") }) else { throw CTAPError.notFIDO2 }
        return info
    }

    /// One CTAP2 command: NFCCTAP_MSG (CLA 80, INS 10), command chaining for payloads over 255 bytes.
    public func command(_ cmd: Command, _ params: CBOR? = nil) async throws -> CBOR? {
        let payload = Data([cmd.rawValue]) + (params?.encoded ?? Data())
        var rest = payload[...]
        var response = Data(), sw: UInt16 = 0
        repeat {
            let chunk = rest.prefix(255)
            rest = rest.dropFirst(chunk.count)
            let cla: UInt8 = rest.isEmpty ? 0x80 : 0x90
            (response, sw) = try await send(Data([cla, 0x10, 0x00, 0x00, UInt8(chunk.count)]) + chunk + (rest.isEmpty ? Data([0x00]) : Data()))
            if !rest.isEmpty && sw != 0x9000 { break }
        } while !rest.isEmpty
        guard sw == 0x9000, let status = response.first else { throw CTAPError.transport(sw: sw) }
        guard status == 0 else { throw CTAPError(status: status) }
        return response.count > 1 ? try CBOR.decode(response.dropFirst()) : nil
    }

    // MARK: getInfo

    public struct Info: Sendable {
        public let versions: [String]
        public let options: [String: Bool]
        public let pinProtocols: [Int]
    }

    public func info() async throws -> Info {
        guard let r = try await command(.getInfo) else { throw CTAPError.malformed }
        var opts: [String: Bool] = [:]
        if case .map(let m)? = r[4] { for (k, v) in m { if let k = k.text, let v = v.bool { opts[k] = v } } }
        return Info(versions: r[1]?.array?.compactMap(\.text) ?? [],
                    options: opts,
                    pinProtocols: r[6]?.array?.compactMap(\.int) ?? [1])
    }

    // MARK: clientPIN

    /// The PIN/UV auth token for getAssertion on `rpId`, from the PIN.
    public func pinToken(pin: String, rpId: String, info: Info) async throws -> (token: Data, proto: PinProtocol) {
        let proto: PinProtocol = info.pinProtocols.contains(2) ? .v2 : .v1
        guard let r = try await command(.clientPIN, .map([(.int(1), .int(proto.rawValue)), (.int(2), .int(2))])),
              let cose = r[1], let x = cose[-2]?.bytes, let y = cose[-3]?.bytes,
              let peer = try? P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y) else { throw CTAPError.malformed }
        let mine = P256.KeyAgreement.PrivateKey()
        let shared = try proto.sharedSecret(mine.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) })
        var pinHash = Data(SHA256.hash(data: Data(pin.utf8)).prefix(16))
        defer { pinHash.resetBytes(in: 0..<pinHash.count) }
        let pinHashEnc = try proto.encrypt(key: shared, pinHash)
        let pub = mine.publicKey.x963Representation
        let keyAgreement = CBOR.map([(.int(1), .int(2)), (.int(3), .int(-25)), (.int(-1), .int(1)),
                                     (.int(-2), .bytes(pub[1..<33])), (.int(-3), .bytes(pub[33..<65]))])
        let params: CBOR
        if info.options["pinUvAuthToken"] == true {
            // CTAP 2.1: a token scoped to getAssertion (permission 0x02) on this rpId only
            params = .map([(.int(1), .int(proto.rawValue)), (.int(2), .int(9)), (.int(3), keyAgreement),
                           (.int(6), .bytes(pinHashEnc)), (.int(9), .int(0x02)), (.int(10), .text(rpId))])
        } else {
            params = .map([(.int(1), .int(proto.rawValue)), (.int(2), .int(5)), (.int(3), keyAgreement), (.int(6), .bytes(pinHashEnc))])
        }
        let resp: CBOR?
        do {
            resp = try await command(.clientPIN, params)
        } catch CTAPError.pinInvalid {
            throw CTAPError.wrongPIN(retriesLeft: (try? await pinRetries()) ?? -1)
        }
        guard let enc = resp?[2]?.bytes else { throw CTAPError.malformed }
        return (try proto.decrypt(key: shared, enc), proto)
    }

    public func pinRetries() async throws -> Int {
        guard let r = try await command(.clientPIN, .map([(.int(1), .int(1)), (.int(2), .int(1))])), let n = r[3]?.int else {
            throw CTAPError.malformed
        }
        return n
    }

    // MARK: getAssertion

    public struct Assertion: Sendable, Equatable {
        public let signature: Data
        public let flags: UInt8
        public let counter: UInt32
    }

    public func getAssertion(rpId: String, clientDataHash: Data, credentialID: Data, userPresence: Bool,
                             pinToken: (token: Data, proto: PinProtocol)?) async throws -> Assertion {
        var params: [(CBOR, CBOR)] = [
            (.int(1), .text(rpId)),
            (.int(2), .bytes(clientDataHash)),
            (.int(3), .array([.map([(.text("id"), .bytes(credentialID)), (.text("type"), .text("public-key"))])])),
            (.int(5), .map([(.text("up"), .bool(userPresence))])),
        ]
        if let p = pinToken {
            params.append((.int(6), .bytes(p.proto.authenticate(key: p.token, clientDataHash))))
            params.append((.int(7), .int(p.proto.rawValue)))
        }
        guard let r = try await command(.getAssertion, .map(params)), let auth = r[2]?.bytes, let sig = r[3]?.bytes,
              auth.count >= 37 else { throw CTAPError.malformed }
        let a = Array(auth)
        guard Data(a[0..<32]) == Data(SHA256.hash(data: Data(rpId.utf8))) else { throw CTAPError.malformed }
        let counter = a[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return Assertion(signature: sig, flags: a[32], counter: counter)
    }
}

/// CTAP2 PIN/UV auth protocols 1 and 2 (CTAP 2.1 §6.5.6, §6.5.7).
public enum PinProtocol: Int, Sendable {
    case v1 = 1, v2 = 2

    /// The shared secret from the ECDH x-coordinate: SHA-256(Z) for v1; HMAC key ‖ AES key (HKDF) for v2.
    func sharedSecret(_ z: Data) throws -> Data {
        switch self {
        case .v1: return Data(SHA256.hash(data: z))
        case .v2:
            let salt = Data(repeating: 0, count: 32)
            func kdf(_ info: String) -> Data {
                HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: z), salt: salt, info: Data(info.utf8), outputByteCount: 32)
                    .withUnsafeBytes { Data($0) }
            }
            return kdf("CTAP2 HMAC key") + kdf("CTAP2 AES key")
        }
    }

    private func aesKey(_ shared: Data) -> Data { self == .v1 ? shared : shared.suffix(32) }
    private func hmacKey(_ key: Data) -> Data { self == .v2 && key.count == 64 ? key.prefix(32) : key }

    func encrypt(key shared: Data, _ plain: Data) throws -> Data {
        switch self {
        case .v1: return try AESCBC.run(CCOperation(kCCEncrypt), key: aesKey(shared), iv: Data(count: 16), plain)
        case .v2:
            var iv = Data(count: 16)
            _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
            return iv + (try AESCBC.run(CCOperation(kCCEncrypt), key: aesKey(shared), iv: iv, plain))
        }
    }

    func decrypt(key shared: Data, _ cipher: Data) throws -> Data {
        switch self {
        case .v1: return try AESCBC.run(CCOperation(kCCDecrypt), key: aesKey(shared), iv: Data(count: 16), cipher)
        case .v2:
            guard cipher.count > 16 else { throw CTAPError.malformed }
            return try AESCBC.run(CCOperation(kCCDecrypt), key: aesKey(shared), iv: cipher.prefix(16), cipher.dropFirst(16))
        }
    }

    /// pinUvAuthParam: HMAC-SHA-256 under the key (the token, or the shared secret's HMAC half), 16 bytes for v1.
    func authenticate(key: Data, _ message: Data) -> Data {
        let mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: hmacKey(key))))
        return self == .v1 ? mac.prefix(16) : mac
    }
}

/// AES-256-CBC without padding (CTAP2 only encrypts whole blocks). CryptoKit has no CBC, CommonCrypto does.
enum AESCBC {
    static func run(_ op: CCOperation, key: Data, iv: Data, _ input: Data) throws -> Data {
        guard key.count == 32, iv.count == 16, input.count % 16 == 0 else { throw CTAPError.malformed }
        var out = Data(count: input.count)
        var moved = 0
        let status = out.withUnsafeMutableBytes { o in
            key.withUnsafeBytes { k in
                iv.withUnsafeBytes { v in
                    input.withUnsafeBytes { i in
                        CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, 32, v.baseAddress,
                                i.baseAddress, input.count, o.baseAddress, input.count, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess, moved == input.count else { throw CTAPError.malformed }
        return out
    }
}

public enum CTAPError: Error, Equatable, LocalizedError {
    case noFIDOApplet, notFIDO2, transport(sw: UInt16), malformed
    case noCredential, pinInvalid, wrongPIN(retriesLeft: Int), pinBlocked, pinAuthBlocked, pinNotSet, pinRequired
    case notAllowed, actionTimeout, status(UInt8)

    init(status: UInt8) {
        switch status {
        case 0x2E: self = .noCredential
        case 0x31: self = .pinInvalid
        case 0x32: self = .pinBlocked
        case 0x34: self = .pinAuthBlocked
        case 0x35: self = .pinNotSet
        case 0x36: self = .pinRequired
        case 0x27: self = .notAllowed
        case 0x2F: self = .actionTimeout
        default: self = .status(status)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .noFIDOApplet: "This key has no FIDO2 applet (or iOS refused to open it)."
        case .notFIDO2: "This key supports only U2F, not FIDO2."
        case .transport(let sw): String(format: "The YubiKey answered with status %04X.", sw)
        case .malformed: "The YubiKey's FIDO2 answer could not be read."
        case .noCredential: "This YubiKey does not hold the requested SSH key. Tap the key the SSH key was made on."
        case .pinInvalid, .wrongPIN(-1): "Wrong FIDO2 PIN."
        case .wrongPIN(let n): "Wrong FIDO2 PIN — \(n) \(n == 1 ? "try" : "tries") left before it locks."
        case .pinBlocked: "The FIDO2 PIN is blocked. Reset FIDO2 on the YubiKey (this deletes its FIDO2 keys)."
        case .pinAuthBlocked: "Too many wrong PINs in a row. Remove the YubiKey from the phone, then try again."
        case .pinNotSet: "This YubiKey has no FIDO2 PIN set, but the SSH key requires one."
        case .pinRequired: "The YubiKey requires the FIDO2 PIN."
        case .notAllowed: "The YubiKey refused the signature."
        case .actionTimeout: "The YubiKey timed out waiting for presence."
        case .status(let s): String(format: "The YubiKey's FIDO2 applet answered with error %02X.", s)
        }
    }
}

/// An OpenSSH sk signature on the YubiKey: select FIDO, PIN → token, getAssertion.
public enum SSHSigner {
    public static func sign(_ s: ApprovalRequest.SSHSign, pin: String, transport: PIVTransport) async throws -> CTAP2.Assertion {
        guard let cred = Data(base64Raw: s.credentialID), let hash = Data(base64Raw: s.clientDataHash), hash.count == 32 else {
            throw CTAPError.malformed
        }
        let ctap = CTAP2(transport)
        try await ctap.select()
        let info = try await ctap.fido2Info()
        var token: (token: Data, proto: PinProtocol)?
        if !pin.isEmpty {
            guard info.options["clientPin"] == true else { throw CTAPError.pinNotSet }
            token = try await ctap.pinToken(pin: pin, rpId: s.application, info: info)
        } else if s.userVerification {
            throw CTAPError.pinRequired
        }
        defer { if var t = token?.token { t.resetBytes(in: 0..<t.count) } }
        return try await ctap.getAssertion(rpId: s.application, clientDataHash: hash, credentialID: cred,
                                           userPresence: s.userPresence, pinToken: token)
    }
}
