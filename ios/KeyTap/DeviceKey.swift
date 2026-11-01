import CryptoKit
import Foundation
import KeyTapCore

/// The phone's signing key. Created in the Secure Enclave when there is one (every real
/// iPhone); the key never leaves it — the keychain only holds the enclave's opaque handle. The
/// simulator has no enclave and gets a software key, which is fine for a test bridge only.
struct SecureEnclaveSigner: DeviceSigner {
    let key: SecureEnclave.P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(_ message: Data) throws -> Data { try key.signature(for: message).derRepresentation }
}

enum DeviceKey {
    private static let account = "device-signing-key"

    static var isHardwareBacked: Bool { SecureEnclave.isAvailable }

    /// The existing key, or a new one.
    static func load(createIfMissing: Bool = true) throws -> DeviceSigner? {
        if let stored = Keychain.get(account) {
            if SecureEnclave.isAvailable {
                return SecureEnclaveSigner(key: try .init(dataRepresentation: stored))
            }
            return try SoftwareSigner(rawRepresentation: stored)
        }
        guard createIfMissing else { return nil }
        if SecureEnclave.isAvailable {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            guard Keychain.set(account, key.dataRepresentation) else { throw KeychainError.writeFailed }
            return SecureEnclaveSigner(key: key)
        }
        let soft = SoftwareSigner()
        guard Keychain.set(account, soft.rawRepresentation) else { throw KeychainError.writeFailed }
        return soft
    }

    static func reset() { Keychain.delete(account) }
}
