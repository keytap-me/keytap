import Foundation
import Security

/// The one secret the Notification Service Extension needs: the notification key shared with the
/// computer. Kept in a keychain access group both targets carry, this device only, readable after
/// the first unlock (notifications arrive while the phone is locked). Never in iCloud or a backup.
public enum SharedKeychain {
    public static let group = "B6Z5PG6RWA.me.keytap.shared"
    static let service = "me.keytap.app.shared"
    static let notifyAccount = "notify-key"

    public static func notifyKey() -> Data? {
        var out: CFTypeRef?
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: notifyAccount,
            kSecAttrAccessGroup as String: group,
            kSecReturnData as String: true,
        ]
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    @discardableResult
    public static func setNotifyKey(_ key: Data?) -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: notifyAccount,
            kSecAttrAccessGroup as String: group,
        ]
        SecItemDelete(base as CFDictionary)
        guard let key else { return true }
        var add = base
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecValueData as String] = key
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
}
