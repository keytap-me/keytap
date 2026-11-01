import SwiftUI

/// The opt-in, used at pairing and in Settings. Says plainly what turning it on changes.
struct NotificationSection: View {
    @Environment(AppModel.self) private var model
    var showStatus = true
    @State private var busy = false

    var body: some View {
        Section {
            HStack {
                Label("Notify Me on This iPhone", systemImage: "bell.badge")
                Spacer()
                Toggle("Notify Me on This iPhone", isOn: Binding(get: { model.notificationsWanted }, set: { on in
                    busy = true
                    Task { await model.setNotifications(on); busy = false }
                }))
                .labelsHidden()
                .disabled(busy)
                .accessibilityIdentifier("notifications-toggle")
            }
            if showStatus, let status {
                Text(status).font(.footnote).foregroundStyle(.secondary)
            }
            if let p = model.pushProblem {
                Text(p).font(.footnote).foregroundStyle(.red)
            }
        } header: {
            Text("Notifications (optional)")
        } footer: {
            Text("Off by default. When on, your computer asks the KeyTap relay (push.keytap.me) to wake this iPhone through Apple's push service when a decryption waits. A notification says only that a request is waiting and when it expires; what it is about, you see in KeyTap. The relay stores nothing. The notification disappears when you answer or after five minutes.")
        }
    }

    private var status: String? {
        guard model.notificationsWanted else { return nil }
        if model.pushToken == nil { return "Registering with Apple…" }
        if model.pairing == nil { return "Sent to your computer when you pair." }
        if model.pushSyncPending {
            return "Not on \(model.pairing?.name ?? "the computer") yet — it is sent the next time the computer is listening, e.g. run age-plugin-yubikey-phone test."
        }
        return "On for \(model.pairing?.name ?? "your computer")."
    }
}
