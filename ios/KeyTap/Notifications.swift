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
            await MainActor.run { model?.pushArrived() } // on screen: the shown request may have ended elsewhere
        }
        return .noData
    }

    /// With KeyTap open the request sheet is already on screen: no banner on top of it. The sound plays
    /// here only if the open app has not sounded this request yet (one sound per request, AppModel).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        guard let id = notification.request.content.userInfo["r"] as? String else { return [] }
        let first = await MainActor.run {
            model?.pushArrived() // fetch the request now rather than at the next scheduled poll
            return model?.claimAlert(id) ?? false
        }
        return first ? [.sound] : []
    }

    /// Tapping the notification opens KeyTap on the request (iOS lets only an app on screen read NFC,
    /// so the PIN and the tap happen there).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let id = response.notification.request.content.userInfo["r"] as? String
        await MainActor.run { model?.notificationOpened(requestID: id) }
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

    /// Its notification is still in Notification Center: it already made its sound.
    static func isDelivered(requestID: String) async -> Bool {
        await UNUserNotificationCenter.current().deliveredNotifications()
            .contains { $0.request.content.userInfo["r"] as? String == requestID }
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

    /// A request appeared while KeyTap is on screen: the sound chosen in Settings (vibration only with
    /// the ring switch off), so the next request is not missed after answering one.
    @MainActor static func chime(_ sound: RequestSound = .current) {
        guard sound != .vibrate, let id = soundID(sound) else {
            AudioServicesPlayAlertSound(kSystemSoundID_Vibrate)
            return
        }
        AudioServicesPlayAlertSound(id)
    }

    @MainActor private static var soundIDs: [RequestSound: SystemSoundID] = [:]

    @MainActor private static func soundID(_ sound: RequestSound) -> SystemSoundID? {
        if let id = soundIDs[sound] { return id }
        let name = (sound.fileName as NSString).deletingPathExtension
        guard let url = Bundle.main.url(forResource: name, withExtension: "wav")
                ?? Bundle.main.url(forResource: name, withExtension: "wav", subdirectory: "Sounds") else { return nil }
        var id: SystemSoundID = 0
        guard AudioServicesCreateSystemSoundID(url as CFURL, &id) == noErr else { return nil }
        soundIDs[sound] = id
        return id
    }
}
