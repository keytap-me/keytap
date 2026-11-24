import Foundation
import Security

/// Generic-password items, readable only while the device is unlocked and never synced to
/// iCloud or restored from a backup (ThisDeviceOnly).
enum Keychain {
    static let service = "me.keytap.app"

    /// nil only if there is no such item. Throws while the item exists but cannot be read: iOS starts KeyTap
    /// in the background on a locked phone (a push, prewarming), and the keychain opens only with the unlock.
    /// "Locked" must never be taken for "empty" — that looks like a phone that was never set up.
    static func read(_ account: String) throws -> Data? {
        var out: CFTypeRef?
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        switch SecItemCopyMatching(q as CFDictionary, &out) {
        case errSecSuccess: return out as? Data
        case errSecItemNotFound: return nil
        default: throw KeychainError.locked
        }
    }

    static func get(_ account: String) -> Data? { try? read(account) }

    @discardableResult
    static func set(_ account: String, _ data: Data) -> Bool {
        delete(account)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
        ]
        return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
    }

    /// Removes every KeyTap item. iOS keeps keychain items after an app is deleted, so a fresh
    /// install calls this once — deleting the app then really deletes everything (privacy policy).
    static func wipeAll() {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(q as CFDictionary)
    }

    static func delete(_ account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }
}
