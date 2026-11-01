import CryptoKit
import Foundation

/// Where the ECDH happens: the YubiKey (over an open NFC session) or a software key (simulator,
/// tests, the Mac soft-phone).
public protocol AgeKey: Sendable {
    /// The compressed recipient point for this identity, or nil if this key does not hold it.
    func recipient(for identity: ApprovalRequest.Identity) async throws -> Data?
    func sharedSecret(for identity: ApprovalRequest.Identity, peer x963: Data) async throws -> Data
}

/// The phone's own key, which signs every answer (Secure Enclave on a device).
public protocol DeviceSigner: Sendable {
    var publicKeyX963: Data { get }
    func sign(_ message: Data) throws -> Data // DER ECDSA-P256-SHA256
}

public struct SoftwareSigner: DeviceSigner {
    let key: P256.Signing.PrivateKey
    public init(key: P256.Signing.PrivateKey = .init()) { self.key = key }
    public init(rawRepresentation: Data) throws { key = try .init(rawRepresentation: rawRepresentation) }
    public var rawRepresentation: Data { key.rawRepresentation }
    public var publicKeyX963: Data { key.publicKey.x963Representation }
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message).derRepresentation }
}

/// A software age-plugin-yubikey-compatible key. Its recipient is a normal `age1yubikey1…`, so
/// `age -r` (with the real plugin) encrypts to it; it pretends to live in retired slot 1 of a
/// made-up serial so a matching identity string can be handed to `age -d -i`.
public struct SoftwareAgeKey: AgeKey {
    public static let fakeSerial: UInt32 = 1
    public static let slot: UInt8 = 0x82
    let key: P256.KeyAgreement.PrivateKey

    public init(key: P256.KeyAgreement.PrivateKey = .init()) { self.key = key }
    public init(rawRepresentation: Data) throws { key = try .init(rawRepresentation: rawRepresentation) }
    public var rawRepresentation: Data { key.rawRepresentation }
    public var recipientPoint: Data { key.publicKey.compressedRepresentation }
    public var recipient: String { PivP256.recipientString(recipientPoint) }
    public var identity: String {
        PivP256.identityString(serial: Self.fakeSerial, slot: Self.slot, tag: PivP256.tag(recipient: recipientPoint))
    }

    public func recipient(for identity: ApprovalRequest.Identity) async throws -> Data? {
        Data(base64Raw: identity.tag) == PivP256.tag(recipient: recipientPoint) ? recipientPoint : nil
    }

    public func sharedSecret(for identity: ApprovalRequest.Identity, peer x963: Data) async throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: x963)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
}

/// The YubiKey over an already-selected, PIN-verified PIV session.
/// The identity file usually lists several YubiKeys (the plugin skips absent ones), so a request
/// carries one stub and one stanza per key. Only the stubs of the TAPPED key are answered: the
/// serial must match, then the slot's public key must hash to the stub's tag. Everything else
/// is skipped, never an error.
public actor YubiKeyAgeKey: AgeKey {
    let piv: PIV
    /// The recipient the operator configured, used when the key's firmware has no GET METADATA.
    let configuredRecipient: Data?
    private var serialRead = false
    private var cachedSerial: UInt32?
    private var slotKeys: [UInt8: Data?] = [:]

    public init(piv: PIV, configuredRecipient: Data?) {
        self.piv = piv
        self.configuredRecipient = configuredRecipient
    }

    /// The tapped key's serial (nil on firmware without GET SERIAL).
    public func serial() async throws -> UInt32? {
        if !serialRead {
            cachedSerial = try await piv.serial()
            serialRead = true
        }
        return cachedSerial
    }

    public func recipient(for identity: ApprovalRequest.Identity) async throws -> Data? {
        if let s = try await serial(), s != identity.serial { return nil }
        let wanted = Data(base64Raw: identity.tag)
        let point: Data?
        if let cached = slotKeys[identity.slot] {
            point = cached
        } else {
            do { point = try await piv.publicKey(slot: identity.slot) } catch PIVError.slotEmpty { point = nil }
            slotKeys[identity.slot] = point
        }
        if let point {
            let compressed = try PivP256.compress(x963: point)
            return PivP256.tag(recipient: compressed) == wanted ? compressed : nil
        }
        if let r = configuredRecipient, PivP256.tag(recipient: r) == wanted { return r }
        return nil
    }

    public func sharedSecret(for identity: ApprovalRequest.Identity, peer x963: Data) async throws -> Data {
        try await piv.ecdh(slot: identity.slot, peer: x963)
    }
}

public enum Approver {
    /// Unwraps every file of the request with `key`. One result per file; a file whose stanzas
    /// all fail carries the last error. File keys never leave this function except in results.
    public static func unwrap(_ request: ApprovalRequest, with key: AgeKey) async throws -> [ApprovalResult] {
        var results: [ApprovalResult] = []
        for file in request.files {
            var result = ApprovalResult(index: file.index, fileKey: nil, error: "no stanza for this key")
            for stanza in file.stanzas {
                guard let identity = request.identities.first(where: { $0.tag == stanza.tag }),
                      let epk = Data(base64Raw: stanza.epk), let body = Data(base64Raw: stanza.body) else { continue }
                do {
                    guard let recipient = try await key.recipient(for: identity) else { continue }
                    let shared = try await key.sharedSecret(for: identity, peer: try PivP256.decompress(epk))
                    let fileKey = try PivP256.unwrap(sharedSecret: shared, epk: epk, recipient: recipient, body: body)
                    result = ApprovalResult(index: file.index, fileKey: fileKey.base64Raw, error: nil)
                    break
                } catch let e as PIVError {
                    // Card-level failures (wrong key, touch refused) apply to the whole session.
                    throw e
                } catch {
                    result.error = "unwrap failed: \(error)"
                }
            }
            results.append(result)
        }
        return results
    }

    public static func answer(_ request: ApprovalRequest, requestBytes: Data, results: [ApprovalResult],
                              signer: DeviceSigner) throws -> ApprovalAnswer {
        let msg = ApprovalAnswer.signedMessage(requestBytes: requestBytes, nonce: request.nonce, declined: false, results: results)
        return ApprovalAnswer(id: request.id, declined: false, results: results, signature: try signer.sign(msg).base64Raw)
    }

    /// The dry run: runs the real key agreement on the key and proves the derived wrap key with
    /// an HMAC over the nonce. Nothing is decrypted and no key material is returned.
    public static func probe(_ request: ApprovalRequest, with key: AgeKey) async throws -> String {
        guard let p = request.probe, let epk = Data(base64Raw: p.epk) else { throw PivP256.Failure.badStanza }
        let identity = ApprovalRequest.Identity(serial: p.serial, slot: p.slot, tag: p.tag)
        guard let recipient = try await key.recipient(for: identity) else { throw PIVError.keyMismatch }
        let shared = try await key.sharedSecret(for: identity, peer: try PivP256.decompress(epk))
        let wrapKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared), salt: epk + recipient, info: PivP256.label, outputByteCount: 32)
        let mac = HMAC<SHA256>.authenticationCode(for: Data("keytap-probe-v1".utf8) + Data(request.nonce.utf8), using: wrapKey)
        return Data(mac).base64Raw
    }

    public static func answerProbe(_ request: ApprovalRequest, requestBytes: Data, proof: String,
                                   signer: DeviceSigner) throws -> ApprovalAnswer {
        let msg = ApprovalAnswer.signedMessage(requestBytes: requestBytes, nonce: request.nonce, declined: false,
                                               results: [], proof: proof)
        return ApprovalAnswer(id: request.id, declined: false, results: [], proof: proof, signature: try signer.sign(msg).base64Raw)
    }

    /// The answer to an SSH request: the YubiKey's assertion, signed into the answer like a file key.
    public static func answerSSH(_ request: ApprovalRequest, requestBytes: Data, assertion: CTAP2.Assertion,
                                 signer: DeviceSigner) throws -> ApprovalAnswer {
        let ssh = SSHAnswer(signature: assertion.signature.base64Raw, flags: assertion.flags, counter: assertion.counter)
        let msg = ApprovalAnswer.signedMessage(requestBytes: requestBytes, nonce: request.nonce, declined: false,
                                               results: [], ssh: ssh)
        return ApprovalAnswer(id: request.id, declined: false, results: [], ssh: ssh, signature: try signer.sign(msg).base64Raw)
    }

    public static func decline(_ request: ApprovalRequest, requestBytes: Data, signer: DeviceSigner) throws -> ApprovalAnswer {
        let msg = ApprovalAnswer.signedMessage(requestBytes: requestBytes, nonce: request.nonce, declined: true, results: [])
        return ApprovalAnswer(id: request.id, declined: true, results: [], signature: try signer.sign(msg).base64Raw)
    }
}
