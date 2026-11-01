import Foundation
import Security

/// The one secret the Notification Service Extension needs: the notification keys shared with the paired
/// computers (one per computer). Kept in a keychain access group both targets carry, this device only, readable
/// after the first unlock (notifications arrive while the phone is locked). Never in iCloud or a backup.
public enum SharedKeychain {
    public static let group = "B6Z5PG6RWA.me.keytap.shared"
    static let service = "me.keytap.app.shared"
    /// KeyTap 1.0 kept a single key under this account; 1.1 uses "notify-key.<computer id>".
    static let legacyAccount = "notify-key"

    static func account(_ computer: String) -> String { "\(legacyAccount).\(computer)" }

    private static func base(_ account: String?) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: group,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    /// Every notification key on this phone. The extension tries each: AES-GCM opens only under the right one.
    public static func notifyKeys() -> [Data] {
        var q = base(nil)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return [] }
        return (out as? [Data]) ?? []
    }

    @discardableResult
    public static func setNotifyKey(_ key: Data?, for computer: String) -> Bool {
        set(key, account: account(computer))
    }

    /// Moves a 1.0 key to the computer it belongs to (the only pairing a 1.0 phone had).
    public static func migrateLegacyNotifyKey(to computer: String) {
        var q = base(legacyAccount)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let key = out as? Data else { return }
        if set(key, account: account(computer)) { set(nil, account: legacyAccount) }
    }

    @discardableResult
    private static func set(_ key: Data?, account: String) -> Bool {
        let b = base(account)
        SecItemDelete(b as CFDictionary)
        guard let key else { return true }
        var add = b
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecValueData as String] = key
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
}
