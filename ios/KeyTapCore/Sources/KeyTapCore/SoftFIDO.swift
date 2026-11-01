import CryptoKit
import Foundation

/// A software FIDO2 authenticator with one Ed25519 credential, speaking CTAP2 over the same APDU interface as the
/// YubiKey's applet (SELECT, NFCCTAP_MSG with chaining, GET RESPONSE). For tests and the Mac soft-phone only:
/// it proves the client side (CBOR, both PIN protocols, getAssertion) end to end, and with `opensshFiles` real
/// ssh can log in with it. Never a real key.
public actor SoftFIDOAuthenticator: PIVTransport {
    public struct Credential: Codable, Sendable {
        public let id: Data
        public let rpId: String
        public let privateKey: Data // Ed25519 raw representation
        public init(rpId: String) {
            self.id = Data((0..<48).map { _ in UInt8.random(in: 0...255) })
            self.rpId = rpId
            self.privateKey = Curve25519.Signing.PrivateKey().rawRepresentation
        }
        public var publicKey: Data { (try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKey))?.publicKey.rawRepresentation ?? Data() }
    }

    let credential: Credential
    /// The credential (for building a demo request; its private key never leaves this actor's process anyway).
    public var credentialForDemo: Credential { credential }
    let pin: String
    let pinUvAuthToken: Bool
    let protocols: [Int]
    let selectReply: String
    let fido2: Bool
    private(set) public var retries = 8
    private var counter: UInt32 = 0
    private let keyAgreement = P256.KeyAgreement.PrivateKey()
    private var token: Data?
    private var selected = false
    private var chain = Data()
    private var pendingOut = Data()

    /// pinUvAuthToken false = a CTAP 2.0 key (getPinToken, no permissions). selectReply "U2F_V2" is what a key that
    /// also speaks U2F answers (every YubiKey 5), "FIDO_2_0" a FIDO2-only key; fido2 false = a U2F-only key.
    public init(credential: Credential, pin: String, pinUvAuthToken: Bool = true, protocols: [Int] = [2, 1],
                selectReply: String = "U2F_V2", fido2: Bool = true) {
        self.credential = credential
        self.pin = pin
        self.pinUvAuthToken = pinUvAuthToken
        self.protocols = protocols
        self.selectReply = selectReply
        self.fido2 = fido2
    }

    // MARK: APDU layer

    public func transmit(_ apdu: Data) async throws -> (data: Data, sw: UInt16) {
        let a = Array(apdu)
        guard a.count >= 4 else { return (Data(), 0x6700) }
        switch (a[0], a[1]) {
        case (0x00, 0xA4):
            let n = a.count > 4 ? Int(a[4]) : 0
            guard a.count >= 5 + n, Data(a[5..<(5 + n)]) == CTAP2.aid else { selected = false; return (Data(), 0x6A82) }
            selected = true
            return out(Data(selectReply.utf8))
        case (0x00, 0xC0):
            return out(Data())
        case (0x80, 0x10), (0x90, 0x10):
            guard selected else { return (Data(), 0x6985) }
            let n = a.count > 4 ? Int(a[4]) : 0
            guard a.count >= 5 + n else { return (Data(), 0x6700) }
            chain += Data(a[5..<(5 + n)])
            if a[0] == 0x90 { return (Data(), 0x9000) }
            let msg = chain
            chain = Data()
            pendingOut = handle(msg)
            return out(Data())
        default:
            return (Data(), 0x6D00)
        }
    }

    /// Sends the next 256 bytes of the pending response; 61xx says more is waiting (exercises GET RESPONSE).
    private func out(_ fresh: Data) -> (data: Data, sw: UInt16) {
        if !fresh.isEmpty { pendingOut = fresh }
        let chunk = pendingOut.prefix(256)
        pendingOut = pendingOut.dropFirst(chunk.count)
        let left = pendingOut.count
        return (Data(chunk), left == 0 ? 0x9000 : 0x6100 | UInt16(min(left, 255)))
    }

    // MARK: CTAP2

    private func handle(_ msg: Data) -> Data {
        guard fido2, let cmd = msg.first else { return Data([0x01]) } // a U2F-only key: CTAP1_ERR_INVALID_COMMAND
        let params = msg.count > 1 ? try? CBOR.decode(msg.dropFirst()) : nil
        switch cmd {
        case 0x04: return ok(.map([
            (.int(1), .array([.text("FIDO_2_0"), .text("FIDO_2_1")])),
            (.int(3), .bytes(Data(count: 16))),
            (.int(4), .map([(.text("rk"), .bool(true)), (.text("up"), .bool(true)), (.text("clientPin"), .bool(true)),
                            (.text("pinUvAuthToken"), .bool(pinUvAuthToken))])),
            (.int(6), .array(protocols.map { .int($0) })),
        ]))
        case 0x06: return clientPIN(params)
        case 0x02: return getAssertion(params)
        default: return Data([0x01]) // CTAP1_ERR_INVALID_COMMAND
        }
    }

    private func ok(_ c: CBOR) -> Data { Data([0x00]) + c.encoded }

    private func clientPIN(_ p: CBOR?) -> Data {
        guard let p, let sub = p[2]?.int else { return Data([0x14]) }
        let proto = PinProtocol(rawValue: p[1]?.int ?? 1) ?? .v1
        switch sub {
        case 1: return ok(.map([(.int(3), .int(retries))]))
        case 2:
            let pub = keyAgreement.publicKey.x963Representation
            return ok(.map([(.int(1), .map([(.int(1), .int(2)), (.int(3), .int(-25)), (.int(-1), .int(1)),
                                            (.int(-2), .bytes(pub[1..<33])), (.int(-3), .bytes(pub[33..<65]))]))]))
        case 5, 9:
            if sub == 9 && (!pinUvAuthToken || p[9]?.int.map({ $0 & 0x02 == 0 }) ?? true) { return Data([0x40]) } // unauthorized permission
            guard retries > 0 else { return Data([0x32]) }
            guard let cose = p[3], let x = cose[-2]?.bytes, let y = cose[-3]?.bytes, let enc = p[6]?.bytes,
                  let peer = try? P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y),
                  let z = try? keyAgreement.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes({ Data($0) }),
                  let shared = try? proto.sharedSecret(z), let pinHash = try? proto.decrypt(key: shared, enc) else { return Data([0x14]) }
            guard pinHash == Data(SHA256.hash(data: Data(pin.utf8)).prefix(16)) else {
                retries -= 1
                return Data([retries == 0 ? 0x32 : 0x31])
            }
            retries = 8
            let t = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            token = t
            guard let encToken = try? proto.encrypt(key: shared, t) else { return Data([0x01]) }
            return ok(.map([(.int(2), .bytes(encToken))]))
        default: return Data([0x02]) // invalid parameter
        }
    }

    private func getAssertion(_ p: CBOR?) -> Data {
        guard let p, let rpId = p[1]?.text, let cdh = p[2]?.bytes, cdh.count == 32 else { return Data([0x14]) }
        let allowed = p[3]?.array?.compactMap { $0["id"]?.bytes } ?? []
        guard rpId == credential.rpId, allowed.contains(credential.id) else { return Data([0x2E]) }
        var uv = false
        if let param = p[6]?.bytes {
            let proto = PinProtocol(rawValue: p[7]?.int ?? 1) ?? .v1
            guard let token, proto.authenticate(key: token, cdh) == param else { return Data([0x33]) }
            uv = true
        }
        let up = p[5]?["up"]?.bool ?? true
        counter += 1
        let flags: UInt8 = (up ? 0x01 : 0) | (uv ? 0x04 : 0)
        var auth = Data(SHA256.hash(data: Data(rpId.utf8)))
        auth.append(flags)
        auth.append(contentsOf: withUnsafeBytes(of: counter.bigEndian, Array.init))
        guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: credential.privateKey),
              let sig = try? key.signature(for: auth + cdh) else { return Data([0x01]) }
        return ok(.map([(.int(1), .map([(.text("id"), .bytes(credential.id)), (.text("type"), .text("public-key"))])),
                        (.int(2), .bytes(auth)), (.int(3), .bytes(sig))]))
    }
}

extension SoftFIDOAuthenticator.Credential {
    /// The OpenSSH key files for this credential, as `ssh-keygen -t ed25519-sk -O resident -O verify-required`
    /// would write them (PROTOCOL.u2f): the private file holds only the key handle, never key material.
    public func opensshFiles(comment: String, verifyRequired: Bool = true) -> (privateKey: String, publicKey: String) {
        func str(_ d: Data) -> Data { withUnsafeBytes(of: UInt32(d.count).bigEndian, { Data($0) }) + d }
        func str(_ s: String) -> Data { str(Data(s.utf8)) }
        let type = "sk-ssh-ed25519@openssh.com"
        let blob = str(type) + str(publicKey) + str(rpId)
        let check = withUnsafeBytes(of: UInt32.random(in: 0...UInt32.max), { Data($0) })
        var priv = check + check + str(type) + str(publicKey) + str(rpId)
        priv.append(0x01 | (verifyRequired ? 0x04 : 0) | 0x20)
        priv += str(id) + str(Data()) + str(comment)
        var pad: UInt8 = 1
        while priv.count % 8 != 0 { priv.append(pad); pad += 1 }
        let body = Data("openssh-key-v1".utf8) + Data([0]) + str("none") + str("none") + str(Data())
            + withUnsafeBytes(of: UInt32(1).bigEndian, { Data($0) }) + str(blob) + str(priv)
        let b64 = body.base64EncodedString().enumerated().map { $0.offset > 0 && $0.offset % 70 == 0 ? "\n\($0.element)" : "\($0.element)" }.joined()
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n\(b64)\n-----END OPENSSH PRIVATE KEY-----\n",
                "\(type) \(blob.base64EncodedString()) \(comment)\n")
    }
}
