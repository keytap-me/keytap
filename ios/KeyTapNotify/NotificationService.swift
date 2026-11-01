import KeyTapCore
import UserNotifications

/// Replaces the generic text of a KeyTap push ("Decryption request — open KeyTap") with the real
/// summary, decrypted on the phone with the key shared only with the paired computer. If anything
/// does not check out (no key, wrong request id, tampered), the generic text stays.
final class NotificationService: UNNotificationServiceExtension {
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var best: UNMutableNotificationContent?

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        best = content
        let info = request.content.userInfo
        // One key per paired computer: only the computer that sent this push has the key that opens it.
        if let payload = info["k"] as? String, let id = info["r"] as? String,
           let s = SharedKeychain.notifyKeys().lazy.compactMap({ NotificationCrypto.open(payload: payload, key: $0, requestID: id) }).first,
           s.expires > .now {
            // Only that something waits and until when: the details stay in the app.
            content.title = s.isSSH ? "SSH sign-in request" : s.isTest ? "Dry run request" : "Decryption request"
            content.subtitle = "Expires \(s.expires.formatted(date: .omitted, time: .shortened))"
            content.body = "Open KeyTap to review it."
            content.threadIdentifier = "keytap"
            content.relevanceScore = 1
        }
        contentHandler(content)
    }

    override func serviceExtensionTimeWillExpire() {
        if let best { contentHandler?(best) }
    }
}
