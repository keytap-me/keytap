import Foundation
import Security

/// The sound for a new request, chosen in Settings. Shared with the notification service extension
/// (through the shared keychain group — the two targets have no app group) so a push sounds the same
/// as a request appearing in the open app. The files are KeyTap's own (scripts/make-sounds.py).
public enum RequestSound: String, CaseIterable, Identifiable, Sendable {
    case rise, ping, glass, knock, pulse, vibrate

    public static let standard = RequestSound.rise
    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .rise: "Rise"
        case .ping: "Ping"
        case .glass: "Glass"
        case .knock: "Knock"
        case .pulse: "Pulse"
        case .vibrate: "Vibrate Only"
        }
    }

    /// The .wav in the app bundle. "Vibrate only" uses a silent file: a push vibrates only with a sound.
    public var fileName: String { self == .vibrate ? "silence.wav" : "\(rawValue).wav" }

    // A separate keychain service: SharedKeychain.notifyKeys() reads every item of its own service.
    private static var query: [String: Any] { [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "me.keytap.app.prefs",
        kSecAttrAccessGroup as String: SharedKeychain.group,
        kSecAttrAccount as String: "request-sound",
    ] }

    public static var current: RequestSound {
        get {
            var q = query
            q[kSecReturnData as String] = true
            var out: CFTypeRef?
            guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data,
                  let s = RequestSound(rawValue: String(decoding: d, as: UTF8.self)) else { return standard }
            return s
        }
        set {
            SecItemDelete(query as CFDictionary)
            var add = query
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecValueData as String] = Data(newValue.rawValue.utf8)
            SecItemAdd(add as CFDictionary, nil)
        }
    }
}
