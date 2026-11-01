import KeyTapCore
import SwiftUI

/// PIN + tap + key agreement, all on the phone: the YubiKey computes a shared secret with an
/// ephemeral key whose private half the phone holds, and the phone checks it in software.
/// Needs no computer and touches no secret — it proves the key is ready for real requests.
struct SelfTestForm: View {
    @Environment(AppModel.self) private var model
    let onPassed: ((PIV.Info) -> Void)?
    @State private var pin = ""
    @State private var busy = false
    @State private var result: PIV.Info?
    @State private var error: String?
    @State private var blocked = false
    @State private var showPUK = false

    var body: some View {
        Form {
            Section {
                Text("Checks that this iPhone can read your YubiKey, that the PIN is accepted and that the tap satisfies the key — without your computer and without decrypting anything.")
                    .font(.callout)
            }
            if !model.useSoftwareKey {
                Section {
                    SecureField("YubiKey PIN", text: $pin)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                        .accessibilityIdentifier("selftest-pin")
                } footer: {
                    Text("The PIN of the YubiKey you will hold to the iPhone. It goes only to that key and is not stored. Three wrong PINs lock it; the PUK unblocks it.")
                }
            }
            Section {
                Button {
                    Task { await run() }
                } label: {
                    HStack {
                        Label("Run Test", systemImage: "key.radiowaves.forward")
                        Spacer()
                        if busy { ProgressView() }
                    }
                }
                .disabled(busy || (!model.useSoftwareKey && !(6...8).contains(pin.count)))
                .accessibilityIdentifier("selftest-run")
            }
            if let r = result {
                Section {
                    Label("PIN accepted", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    Label("Tap satisfied the key", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    Label("Key agreement verified", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    if let s = r.serial { LabeledContent("Serial", value: String(s)) }
                    if let f = r.firmware { LabeledContent("Firmware", value: f) }
                    LabeledContent("Touch policy", value: CheckKeyView.touch(r.touchPolicy))
                } header: {
                    Text("Ready")
                }
            }
            if let error {
                Section {
                    Text(error).foregroundStyle(.red)
                    if blocked {
                        Button("Unblock the PIN with the PUK", systemImage: "lock.open") { showPUK = true }
                    }
                }
            }
        }
        .sheet(isPresented: $showPUK) {
            PUKSheet(serial: nil, label: { "YubiKey \($0)" }) {
                showPUK = false
                blocked = false
                error = "PIN changed. Run the test with the new PIN."
            }
            .environment(model)
        }
    }

    private func run() async {
        busy = true
        error = nil
        result = nil
        let p = pin
        pin = ""
        defer { busy = false }
        do {
            let slot = CheckKeyView.slot
            let r = try await model.selfTest(pin: p, slot: slot)
            result = r
            onPassed?(r)
        } catch NFCError.cancelled {
        } catch PIVError.pinBlocked {
            blocked = true
            error = PIVError.pinBlocked.errorDescription
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}
