import AudioToolbox
import KeyTapCore
import UIKit
import UserNotifications

/// Optional push support. The phone's push token goes only to the paired computer (which hands it
/// to the relay per request); the notification text is decrypted on the phone by KeyTapNotify.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    @MainActor weak var model: AppModel?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in model?.didRegisterForPush(token: hex) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in model?.pushRegistrationFailed(error) }
    }

    /// The silent "clear" push: the request was answered, declined or expired on the computer.
    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult {
        if let id = userInfo["clear"] as? String {
            await Notifications.remove(requestID: id)
            await Notifications.badgeFromDelivered()
        }
        return .noData
    }

    /// With KeyTap open the request sheet is already on screen: no banner on top of it (the app chimes
    /// itself when the poll shows the request, see AppModel.poll).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        []
    }

    /// Tapping the notification opens KeyTap on the request (iOS lets only an app on screen read NFC,
    /// so the PIN and the tap happen there).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await MainActor.run { model?.notificationOpened() }
    }
}

enum Notifications {
    /// Removes delivered notifications for one request (or every expired one when id is nil).
    static func remove(requestID: String?) async {
        let center = UNUserNotificationCenter.current()
        let delivered = await center.deliveredNotifications()
        let ids = delivered.filter { n in
            guard let r = n.request.content.userInfo["r"] as? String else { return false }
            return requestID == nil ? n.date < Date().addingTimeInterval(-120) : r == requestID
        }.map(\.request.identifier)
        if !ids.isEmpty { center.removeDeliveredNotifications(withIdentifiers: ids) }
    }

    /// 1 while a request waits, 0 once none does. Needs notification permission with badges.
    static func setBadge(_ n: Int) {
        UNUserNotificationCenter.current().setBadgeCount(n) { _ in }
    }

    /// In the background the app knows only the delivered notifications: badge while one is left.
    static func badgeFromDelivered() async {
        let left = await UNUserNotificationCenter.current().deliveredNotifications()
            .contains { $0.request.content.userInfo["r"] != nil }
        try? await UNUserNotificationCenter.current().setBadgeCount(left ? 1 : 0)
    }

    /// A request appeared while KeyTap is on screen: the system's notification sound (vibration only
    /// with the ring switch off), so the next request is not missed after answering one.
    static func chime() {
        AudioServicesPlayAlertSound(SystemSoundID(1007))
    }
}
