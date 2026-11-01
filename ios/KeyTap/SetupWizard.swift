import KeyTapCore
import SwiftUI

/// First run, and "Set up again": explains KeyTap, walks through preparing the computer, pairs,
/// registers the YubiKey, then proves PIN + tap on the phone and the whole chain with a dry run.
struct SetupWizard: View {
    @Environment(AppModel.self) private var model
    @Binding var incomingLink: PairingLink?
    @State private var path: [Step] = []

    enum Step: Hashable { case computer, pair, selfTest, dryRun }

    var body: some View {
        NavigationStack(path: $path) {
            WelcomeStep { path.append(.computer) }
                .navigationDestination(for: Step.self) { step in
                    switch step {
                    case .computer: ComputerStep { path.append(.pair) }
                    case .pair: PairStep(incomingLink: $incomingLink) { path.append(.selfTest) }
                    case .selfTest: SelfTestStep { path.append(.dryRun) }
                    case .dryRun: DryRunStep { model.setupDone = true }
                    }
                }
        }
        .onChange(of: incomingLink) { _, link in
            // A pairing link opened from outside jumps straight to the pairing step.
            if link != nil, !path.contains(.pair) { path = [.computer, .pair] }
        }
    }
}

// MARK: 1 — what and why

private struct WelcomeStep: View {
    @Environment(AppModel.self) private var model
    let next: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Image(systemName: "key.radiowaves.forward.fill")
                    .font(.system(size: 56)).foregroundStyle(.tint)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 24)
                Text("Your hardware key, from anywhere")
                    .font(.largeTitle.bold())
                Text("KeyTap lets you approve a decryption on your computer by tapping your YubiKey® against this iPhone — when the key is with you and the computer is not.")
                    .foregroundStyle(.secondary)
                Feature(symbol: "lock.shield", title: "Still key, PIN and touch",
                        text: "The key agreement happens on the YubiKey. Its PIN goes only to the key. Nothing on the computer can decrypt without you.")
                Feature(symbol: "network.slash", title: "No server, no account",
                        text: "KeyTap talks only to your own computer, directly over your network or VPN. No cloud, nothing collected. Notifications are optional and end-to-end encrypted.")
                Feature(symbol: "eye", title: "You see what you approve",
                        text: "Every request shows the command, the file and a code that your terminal shows too.")
                NavigationLink("How KeyTap works and why it is secure") { DocsView() }
                    .font(.callout)
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                Button(action: next) { Text("Set Up").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                Button("Try the Demo") { model.startDemo() }
                    .font(.callout)
                    .accessibilityIdentifier("try-demo")
            }
            .padding(.horizontal, 24).padding(.bottom, 8)
        }
        .navigationTitle("")
    }
}

private struct Feature: View {
    let symbol: String
    let title: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: symbol).font(.title2).foregroundStyle(.tint).frame(width: 32)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(text).font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: 2 — prepare the computer

private struct ComputerStep: View {
    let next: () -> Void
    @State private var platform: Platform = .unix

    enum Platform: String, CaseIterable, Identifiable {
        case unix = "macOS · Linux", windows = "Windows"
        var id: String { rawValue }
    }

    var body: some View {
        List {
            Section {
                Text("Do this once on the computer you want to decrypt on. Tap a command to copy it.")
                    .font(.callout)
                Picker("System", selection: $platform) {
                    ForEach(Platform.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
            }
            Section {
                CommandRow(platform == .unix ? "brew install age age-plugin-yubikey" : "winget install FiloSottile.age")
                Text(platform == .unix
                     ? "On Linux use your distribution's packages. Your YubiKey needs an age key: if it has none yet, run `age-plugin-yubikey` and follow its prompts. It never touches a slot that is in use."
                     : "Also install age-plugin-yubikey for Windows from its GitHub releases. Your YubiKey needs an age key: if it has none yet, run `age-plugin-yubikey` and follow its prompts.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: { Text("1 · age and the YubiKey plugin") }
            Section {
                CommandRow(platform == .unix
                           ? "curl -fsSL https://keytap.me/get | sh -s -- --shim"
                           : "& ([scriptblock]::Create((irm https://keytap.me/install.ps1))) -Shim")
                Text("Installs the KeyTap bridge from its public GitHub release after checking the checksum, and puts it ahead of the real plugin so age and sops ask this iPhone. Encryption keeps working: the bridge hands it to the real plugin. Read the script first if you like — it is short.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: { Text("2 · The KeyTap bridge") }
            Section {
                CommandRow("age-plugin-yubikey-phone pair --host <IP of this computer>")
                Text("Use the address this iPhone reaches the computer at — on macOS `ipconfig getifaddr en0`, or the computer's address in your VPN. The computer listens on that address only. The command prints a pairing link: copy it, then continue here.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: { Text("3 · Start pairing") }
            Section {
                Link(destination: Links.install) {
                    Label("Full guide, manual install and uninstall", systemImage: "safari")
                }
            }
        }
        .navigationTitle("Prepare Your Computer")
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) {
            Button(action: next) { Text("I Have the Pairing Link").frame(maxWidth: .infinity) }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .padding(.horizontal, 24).padding(.bottom, 8)
        }
    }
}

struct CommandRow: View {
    let command: String
    @State private var copied = false
    init(_ command: String) { self.command = command }

    var body: some View {
        Button {
            UIPasteboard.general.string = command
            copied = true
            Task { try? await Task.sleep(for: .seconds(1.5)); copied = false }
        } label: {
            HStack(alignment: .firstTextBaseline) {
                Text(command).font(.callout.monospaced()).foregroundStyle(.primary).multilineTextAlignment(.leading)
                Spacer(minLength: 8)
                Image(systemName: copied ? "checkmark" : "doc.on.doc").foregroundStyle(.tint)
            }
        }
        .accessibilityHint("Copies the command")
    }
}

// MARK: 3 — pair and register the YubiKey

private struct PairStep: View {
    @Environment(AppModel.self) private var model
    @Binding var incomingLink: PairingLink?
    let next: () -> Void
    @State private var pasted = ""
    @State private var link: PairingLink?
    @State private var slot: UInt8 = 0x82
    @State private var yubikeys: [BridgeClient.RegisteredKey] = []
    @State private var busy = false
    @State private var error: String?
    @State private var networkDenied = false

    var body: some View {
        Form {
            Section {
                TextField("keytap://pair?…", text: $pasted, axis: .vertical)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("pairing-link")
                Button("Paste from Clipboard", systemImage: "doc.on.clipboard") {
                    pasted = UIPasteboard.general.string ?? ""
                }
            } header: {
                Text("Pairing link")
            } footer: {
                if !pasted.isEmpty && link == nil { Text("That is not a KeyTap pairing link.").foregroundStyle(.red) }
            }
            if let link {
                Section("Computer") {
                    LabeledContent("Name", value: link.name)
                    LabeledContent("Address", value: link.host)
                    LabeledContent("Certificate", value: link.pin.prefix(6).map { String(format: "%02x", $0) }.joined())
                }
                Section {
                    ForEach(yubikeys, id: \.serial) { k in
                        LabeledContent {
                            Text(PivP256.recipientString(Data(base64Raw: k.recipient) ?? Data()))
                                .font(.caption2.monospaced()).lineLimit(1).truncationMode(.middle)
                        } label: {
                            Label("YubiKey \(k.serial)", systemImage: "checkmark.circle.fill")
                        }
                    }
                    .onDelete { yubikeys.remove(atOffsets: $0) }
                    Button(yubikeys.isEmpty ? "Tap YubiKey to Register It" : "Add Another YubiKey",
                           systemImage: yubikeys.isEmpty ? "key.radiowaves.forward" : "plus.circle") {
                        Task { await readKey() }
                    }
                    .disabled(busy)
                    .accessibilityIdentifier("register-yubikey")
                    DisclosureGroup("Advanced") {
                        Picker("PIV slot", selection: $slot) {
                            ForEach(0..<20, id: \.self) { i in
                                Text("Retired \(i + 1)\(i == 0 ? " (default)" : "")").tag(UInt8(0x82 + i))
                            }
                        }
                    }
                } header: {
                    Text("Your YubiKey")
                } footer: {
                    Text("Tap each YubiKey you want to use with this phone — one is enough. Reads the serial number and the age key's public half; no PIN, nothing is changed. The computer asks this phone only about registered keys and skips the others.")
                }
                NotificationSection(showStatus: false)
                Section {
                    Button {
                        Task { await pair(link) }
                    } label: {
                        HStack {
                            Text("Pair with \(link.name)")
                            Spacer()
                            if busy { ProgressView() }
                        }
                    }
                    .disabled(busy || yubikeys.isEmpty)
                    .accessibilityIdentifier("pair")
                } footer: {
                    Text(DeviceKey.isHardwareBacked
                         ? "A signing key is created in this iPhone's Secure Enclave. It never leaves the device."
                         : "No Secure Enclave here — a software signing key is used. For testing only.")
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Pair")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: pasted) { _, s in link = PairingLink(s) }
        .onAppear(perform: takeIncomingLink)
        .onChange(of: incomingLink) { _, _ in takeIncomingLink() }
        .localNetworkAlert(isPresented: $networkDenied)
    }

    /// A link opened from outside always wins, also when this step is already on screen.
    private func takeIncomingLink() {
        guard let l = incomingLink else { return }
        link = l
        pasted = ""
        error = nil
        incomingLink = nil
    }

    private func readKey() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            let k = try await model.readYubiKey(slot: slot)
            if let i = yubikeys.firstIndex(where: { $0.serial == k.serial }) {
                yubikeys[i] = k // read again: keep the latest
            } else {
                yubikeys.append(k)
            }
        } catch NFCError.cancelled {
        } catch PIVError.slotEmpty {
            error = "This YubiKey has no age key in that slot. Create one with age-plugin-yubikey on the computer, or pick the slot it uses under Advanced."
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    private func pair(_ link: PairingLink) async {
        guard !yubikeys.isEmpty else { return }
        busy = true
        error = nil
        defer { busy = false }
        switch await NetworkProbe.check(link.host) {
        case .reachable: break
        case .localNetworkDenied:
            networkDenied = true
            return
        case .notListening:
            error = "\(link.name) answers, but is not waiting for a pairing. Run the pair command again (it waits ten minutes) and paste the new link."
            return
        case .unreachable(let why):
            error = why
            return
        }
        do {
            try await model.pair(with: link, keys: yubikeys)
            next()
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}

// MARK: 4 — prove PIN + tap on the phone

private struct SelfTestStep: View {
    let next: () -> Void

    var body: some View {
        SelfTestForm(onPassed: nil)
            .navigationTitle("Test Your YubiKey")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarBackButtonHidden()
            .safeAreaInset(edge: .bottom) {
                Button(action: next) { Text("Continue").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .padding(.horizontal, 24).padding(.bottom, 8)
                    .accessibilityIdentifier("continue")
            }
    }
}

// MARK: 5 — the dry run through the computer

private struct DryRunStep: View {
    @Environment(AppModel.self) private var model
    let finish: () -> Void

    var body: some View {
        List {
            Section {
                Text("Last step: a dry run through the computer. It uses everything a real decryption uses — the bridge, the network, this phone, your PIN and a tap — but nothing is decrypted.")
                    .font(.callout)
            }
            Section {
                CommandRow("age-plugin-yubikey-phone test")
            } header: {
                Text("Run on \(model.pairing?.name ?? "the computer")")
            } footer: {
                Text("Keep KeyTap open. The request appears here within a few seconds.")
            }
            Section {
                if model.dryRunPassed {
                    Label("Dry run passed. KeyTap is ready.", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                } else {
                    Label { Text(status) } icon: { ProgressView() }
                }
            }
        }
        .navigationTitle("Dry Run")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden()
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                Button(action: finish) { Text("Done").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(!model.dryRunPassed)
                    .accessibilityIdentifier("done")
                if !model.dryRunPassed {
                    Button("Skip for Now", action: finish).font(.callout)
                }
            }
            .padding(.horizontal, 24).padding(.bottom, 8)
        }
    }

    private var status: String {
        switch model.link {
        case .error(let e): e
        default: "Waiting for the dry run…"
        }
    }
}

// MARK: shared

extension View {
    /// After a "Don't Allow", iOS never asks again: the user has to switch Local Network on in Settings.
    func localNetworkAlert(isPresented: Binding<Bool>) -> some View {
        alert("Local Network Access Is Off", isPresented: isPresented) {
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("KeyTap needs it to reach your computer. In Settings ▸ KeyTap, switch on Local Network, then try again.")
        }
    }
}
