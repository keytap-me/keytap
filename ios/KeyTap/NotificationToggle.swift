import KeyTapCore
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
            Text("Off by default. When on, your computer asks the KeyTap relay (push.keytap.me) to wake this iPhone through Apple's push service when a decryption or an SSH sign-in waits. A notification says only that a request is waiting and when it expires; what it is about, you see in KeyTap. The relay stores nothing. The notification disappears when you answer or after five minutes.")
        }
    }

    private var status: String? {
        guard model.notificationsWanted else { return nil }
        if model.pushToken == nil { return "Registering with Apple…" }
        if model.pairings.isEmpty { return "Sent to your computer when you pair." }
        let waiting = model.pairings.filter { model.pushPending.contains($0.id) }.map(\.name)
        if !waiting.isEmpty {
            return "Not on \(waiting.joined(separator: ", ")) yet — it is sent the next time that computer is listening, e.g. run age-plugin-yubikey-phone test."
        }
        return "On for \(model.pairings.map(\.name).joined(separator: ", "))."
    }
}

/// The sound of a new request: in the open app, and for a notification when they are on.
struct RequestSoundSection: View {
    @State private var sound = RequestSound.current

    var body: some View {
        Section {
            Picker(selection: $sound) {
                ForEach(RequestSound.allCases) { s in Text(s.title).tag(s) }
            } label: {
                Label("Request Sound", systemImage: "speaker.wave.2")
            }
            .pickerStyle(.navigationLink)
            .accessibilityIdentifier("request-sound")
            .onChange(of: sound) { _, s in
                RequestSound.current = s
                Notifications.chime(s) // preview
            }
        } footer: {
            Text("Played when a request arrives while KeyTap is open, and for its notification. With the Ring/Silent switch on silent, the iPhone vibrates instead.")
        }
    }
}
