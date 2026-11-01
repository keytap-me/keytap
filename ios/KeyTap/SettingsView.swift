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
                if !model.pairings.isEmpty {
                    Section {
                        ForEach(model.pairings) { p in
                            NavigationLink { ComputerView(pairing: p) } label: {
                                LabeledContent {
                                    Text(p.host).font(.caption.monospaced())
                                } label: {
                                    Label(p.name, systemImage: "desktopcomputer")
                                }
                            }
                        }
                        Button("Add a Computer", systemImage: "plus.circle") { model.setupDone = false; dismiss() }
                            .accessibilityIdentifier("add-computer")
                    } header: {
                        Text("Computers")
                    } footer: {
                        Text("This iPhone answers every computer paired here — a laptop, a desktop at home, a workstation at the office. Pairing the same computer again replaces its pairing, e.g. to register other YubiKeys.")
                    }
                    NotificationSection()
                }
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
                    Link(destination: Links.source) { Label("Source Code", systemImage: "chevron.left.forwardslash.chevron.right") }
                } footer: {
                    Text("KeyTap \(AppInfo.version). The links open keytap.me or GitHub in Safari; the app itself only ever talks to your computer.")
                }
                Section {
                    Button("Remove All Computers", role: .destructive) { confirmForget = true }
                } footer: {
                    Text("Also deletes this iPhone's signing key. On each computer, remove the phone too: `age-plugin-yubikey-phone unpair \"\(UIDevice.current.name)\"`.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Done") { dismiss() } }
            .confirmationDialog("Remove all computers from this iPhone?", isPresented: $confirmForget, titleVisibility: .visible) {
                Button("Remove All", role: .destructive) {
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

/// One paired computer: where it is, which YubiKeys it asks about, and removing it.
private struct ComputerView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let pairing: Pairing
    @State private var confirmRemove = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: pairing.name)
                LabeledContent("Address", value: pairing.host)
                LabeledContent("Certificate", value: pairing.pin.prefix(6).map { String(format: "%02x", $0) }.joined())
                LabeledContent("Status", value: status)
                if let r = pairing.recipient {
                    LabeledContent("Recipient") { Text(r).font(.caption2.monospaced()).lineLimit(1).truncationMode(.middle) }
                }
            }
            if let keys = pairing.keys, !keys.isEmpty {
                Section {
                    ForEach(keys, id: \.serial) { k in
                        LabeledContent("YubiKey \(k.serial)", value: "Retired slot \(Int(k.slot) - 0x81)")
                    }
                } header: {
                    Text("Registered YubiKeys")
                } footer: {
                    Text("For decryptions, this computer asks only about these keys. SSH sign-ins work with any YubiKey that holds the SSH key. To change the list, pair this computer again with the keys at hand.")
                }
            }
            Section {
                Button("Remove \(pairing.name)", role: .destructive) { confirmRemove = true }
            } footer: {
                Text("On \(pairing.name), remove this iPhone too: `age-plugin-yubikey-phone unpair \"\(UIDevice.current.name)\"`.")
            }
        }
        .navigationTitle(pairing.name)
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Remove \(pairing.name) from this iPhone?", isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) {
                model.remove(pairing)
                dismiss()
            }
        }
    }

    private var status: String {
        switch model.links[pairing.id] ?? .unknown {
        case .unknown: "Connecting…"
        case .waiting: "Reachable"
        case .notListening: "Ready (nothing waiting)"
        case .error(let e): e
        }
    }
}
