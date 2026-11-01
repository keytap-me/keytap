import KeyTapCore
import SwiftUI

/// Reads the YubiKey over NFC without changing anything: firmware, serial, and the age slot's
/// PIN/touch policy and public key. No PIN is asked for and nothing is written.
struct CheckKeyView: View {
    @Environment(AppModel.self) private var model
    @State private var info: PIV.Info?
    @State private var error: String?
    @State private var busy = false
    static let slot: UInt8 = 0x82 // age-plugin-yubikey "slot 1"

    var body: some View {
        Form {
            Section {
                Button {
                    Task { await check() }
                } label: {
                    HStack {
                        Label("Tap YubiKey", systemImage: "key.radiowaves.forward")
                        Spacer()
                        if busy { ProgressView() }
                    }
                }
                .disabled(busy || !NFCPIVSession.isAvailable)
            } footer: {
                Text("Reads the key without changing it. No PIN needed.")
            }
            if let info {
                Section("YubiKey") {
                    LabeledContent("Firmware", value: info.firmware ?? "—")
                    LabeledContent("Serial", value: info.serial.map(String.init) ?? "—")
                    LabeledContent("PIN tries left", value: info.pinRetries.map(String.init) ?? "—")
                }
                Section("Age slot (retired 1, 0x82)") {
                    LabeledContent("PIN policy", value: Self.pin(info.pinPolicy))
                    LabeledContent("Touch policy", value: Self.touch(info.touchPolicy))
                    if let r = recipient(info) {
                        LabeledContent("Recipient") { Text(r).font(.caption2.monospaced()).lineLimit(1).truncationMode(.middle) }
                    }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("Check YubiKey")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func recipient(_ i: PIV.Info) -> String? {
        i.publicKey.flatMap { try? PivP256.compress(x963: $0) }.map(PivP256.recipientString)
    }

    private func check() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            info = try await NFCPIVSession.run(prompt: "Hold your YubiKey to the top of the iPhone.", done: "Read.") { t in
                let piv = PIV(t)
                try await piv.select()
                return try await piv.info(slot: Self.slot)
            }
        } catch NFCError.cancelled {
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    static func pin(_ p: UInt8?) -> String {
        switch p { case 1: "Never"; case 2: "Once per session"; case 3: "Always"; default: "—" }
    }

    static func touch(_ t: UInt8?) -> String {
        switch t { case 1: "Never"; case 2: "Always"; case 3: "Cached (15 s)"; default: "—" }
    }
}
