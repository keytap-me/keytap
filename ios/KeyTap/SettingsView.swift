import KeyTapCore
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var confirmForget = false

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Form {
                if let p = model.pairing {
                    Section("Workstation") {
                        LabeledContent("Name", value: p.name)
                        LabeledContent("Address", value: p.host)
                        LabeledContent("Certificate", value: p.pin.prefix(6).map { String(format: "%02x", $0) }.joined())
                        if let r = p.recipient {
                            LabeledContent("Recipient") { Text(r).font(.caption2.monospaced()).lineLimit(1).truncationMode(.middle) }
                        }
                    }
                }
                if let keys = model.pairing?.keys, !keys.isEmpty {
                    Section {
                        ForEach(keys, id: \.serial) { k in
                            LabeledContent("YubiKey \(k.serial)", value: "Retired slot \(Int(k.slot) - 0x81)")
                        }
                    } header: {
                        Text("Registered YubiKeys")
                    } footer: {
                        Text("To add or remove a key, use Set Up Again with the keys at hand.")
                    }
                }
                if model.pairing != nil { NotificationSection() }
                Section {
                    NavigationLink("Test YubiKey (PIN + Tap)") {
                        SelfTestForm(onPassed: nil).navigationTitle("Test YubiKey").navigationBarTitleDisplayMode(.inline)
                    }
                    NavigationLink("Check YubiKey") { CheckKeyView() }
                    LabeledContent("NFC", value: NFCPIVSession.isAvailable ? "Available" : "Not available")
                    LabeledContent("Signing key", value: DeviceKey.isHardwareBacked ? "Secure Enclave" : "Software (test)")
                }
                #if DEBUG
                Section {
                    Toggle("Use software test key", isOn: $model.useSoftwareKey)
                    if let k = try? SoftwareTestKey.load() {
                        CopyRow(label: "Recipient", value: k.recipient)
                        CopyRow(label: "Identity", value: k.identity)
                    }
                } header: {
                    Text("Testing")
                } footer: {
                    Text("Debug builds only. Encrypt a throwaway file to this recipient; decrypt with this identity through the bridge.")
                }
                #endif
                Section {
                    NavigationLink("About KeyTap") { DocsView() }
                    NavigationLink("Legal") { LegalView() }
                    Link(destination: Links.install) { Label("Install Guide", systemImage: "safari") }
                    Link(destination: Links.privacy) { Label("Privacy Policy", systemImage: "hand.raised") }
                    Link(destination: Links.support) { Label("Support", systemImage: "questionmark.circle") }
                    Link(destination: Links.source) { Label("Bridge Source Code", systemImage: "chevron.left.forwardslash.chevron.right") }
                } footer: {
                    Text("KeyTap \(AppInfo.version). The links open keytap.me or GitHub in Safari; the app itself only ever talks to your computer.")
                }
                Section {
                    Button("Set Up Again") { model.setupDone = false; dismiss() }
                } footer: {
                    Text("Runs the setup again: a new pairing link, another computer, or other YubiKeys. The current pairing stays until the new one replaces it.")
                }
                Section {
                    Button("Unpair", role: .destructive) { confirmForget = true }
                } footer: {
                    Text("Also remove it on the workstation: `age-plugin-yubikey-phone unpair \"\(UIDevice.current.name)\"`.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Done") { dismiss() } }
            .confirmationDialog("Unpair this iPhone?", isPresented: $confirmForget, titleVisibility: .visible) {
                Button("Unpair", role: .destructive) {
                    model.forget()
                    dismiss()
                }
            }
        }
    }
}

private struct CopyRow: View {
    let label: String
    let value: String

    var body: some View {
        Button {
            UIPasteboard.general.string = value
        } label: {
            LabeledContent(label) {
                Text(value).font(.caption2.monospaced()).lineLimit(1).truncationMode(.middle)
            }
        }
        .tint(.primary)
    }
}
