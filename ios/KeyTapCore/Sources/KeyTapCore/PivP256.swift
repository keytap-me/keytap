import CryptoKit
import Foundation

/// The age-plugin-yubikey `piv-p256` recipient type, verified against str4d/age-plugin-yubikey
/// v0.5.1 (src/format.rs, src/p256.rs, src/key.rs):
///
///     stanza   -> piv-p256 <tag: 4 bytes> <epk: 33 bytes, SEC1 compressed>
///              <body: 32 bytes>
///     tag      = SHA-256(compressed recipient)[0..<4]
///     shared   = ECDH(slot key, epk)  — the x-coordinate, 32 bytes (what the YubiKey returns)
///     wrap key = HKDF-SHA256(ikm: shared, salt: epk ‖ compressed recipient, info: "piv-p256", 32)
///     body     = ChaCha20-Poly1305(wrap key, nonce: 12 zero bytes, file key: 16 bytes) ‖ tag
///     identity = bech32("age-plugin-yubikey-", serial u32 LE ‖ retired slot (0x82…0x95) ‖ tag)
///     recipient= bech32("age1yubikey", compressed point)
public enum PivP256 {
    public static let recipientHRP = "age1yubikey"
    public static let identityHRP = "age-plugin-yubikey-"
    static let label = Data("piv-p256".utf8)

    public enum Failure: Error, Equatable {
        case badStanza
        case unwrapFailed
        case badRecipient
    }

    public static func tag(recipient compressed: Data) -> Data {
        Data(SHA256.hash(data: compressed).prefix(4))
    }

    /// Unwraps the 16-byte file key once the ECDH has been done (on the YubiKey or in software).
    public static func unwrap(sharedSecret: Data, epk: Data, recipient: Data, body: Data) throws -> Data {
        guard sharedSecret.count == 32, epk.count == 33, recipient.count == 33, body.count == 32 else {
            throw Failure.badStanza
        }
        let wrapKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: epk + recipient,
            info: label,
            outputByteCount: 32
        )
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: Data(count: 12)),
                ciphertext: body.prefix(16),
                tag: body.suffix(16)
            )
            return try ChaChaPoly.open(box, using: wrapKey)
        } catch {
            throw Failure.unwrapFailed
        }
    }

    /// The uncompressed X9.63 point of a compressed epk — the form PIV GENERAL AUTHENTICATE takes.
    public static func decompress(_ epk: Data) throws -> Data {
        do {
            return try P256.KeyAgreement.PublicKey(compressedRepresentation: epk).x963Representation
        } catch {
            throw Failure.badStanza
        }
    }

    public static func compress(x963 point: Data) throws -> Data {
        do {
            return try P256.KeyAgreement.PublicKey(x963Representation: point).compressedRepresentation
        } catch {
            throw Failure.badRecipient
        }
    }

    public static func recipientString(_ compressed: Data) -> String {
        Bech32.encode(hrp: recipientHRP, data: compressed)
    }

    public static func parseRecipient(_ s: String) -> Data? {
        guard let (hrp, data) = Bech32.decode(s.trimmingCharacters(in: .whitespacesAndNewlines)),
              hrp == recipientHRP, data.count == 33, data[0] == 2 || data[0] == 3 else { return nil }
        return data
    }

    public static func identityString(serial: UInt32, slot: UInt8, tag: Data) -> String {
        var d = withUnsafeBytes(of: serial.littleEndian) { Data($0) }
        d.append(slot)
        d.append(tag)
        return Bech32.encode(hrp: identityHRP, data: d).uppercased()
    }

    /// Wraps a file key to a recipient exactly as age-plugin-yubikey does — for tests and the
    /// software path only; real files are encrypted by `age` itself.
    public static func wrap(fileKey: Data, recipient: Data) throws -> (tag: Data, epk: Data, body: Data) {
        let pk = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipient)
        let esk = P256.KeyAgreement.PrivateKey()
        let epk = esk.publicKey.compressedRepresentation
        let shared = try esk.sharedSecretFromKeyAgreement(with: pk).withUnsafeBytes { Data($0) }
        let wrapKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared), salt: epk + recipient, info: label, outputByteCount: 32)
        let box = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: ChaChaPoly.Nonce(data: Data(count: 12)))
        return (tag(recipient: recipient), epk, Data(box.ciphertext) + Data(box.tag))
    }
}
