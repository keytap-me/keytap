import KeyTapCore
import SwiftUI

/// The request in plain words. Someone in control of the workstation could ride along on an
/// approval, so the operator sees exactly what asked, where, and the code their terminal shows.
/// Fits one screen: the details are condensed, the PIN and the actions are pinned to the bottom.
struct RequestView: View {
    @Environment(AppModel.self) private var model
    let request: ApprovalRequest
    @State private var pin = ""
    @State private var busy = false
    @State private var error: String?
    @State private var showCommand = false
    /// The key the PIN is for. Preselected from the computer's default (the key last used there); the phone
    /// stores nothing. Tapping a different key sends no PIN.
    @State private var picked: UInt32?
    @State private var lastTry = false
    @State private var pinBlocked = false
    @State private var showPUK = false
    /// Set once, when the expiry passes (a single wake-up, not a redraw of the sheet every second).
    @State private var expired = false
    @FocusState private var pinFocused: Bool

    private var keys: [ApprovalRequest.KeyInfo] { request.offeredKeys }
    private var pickedLabel: String? { picked.map { request.label(of: $0) } }

    var body: some View {
        NavigationStack {
            List {
                if let note = request.displayNote {
                    Section {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("Note from \(request.user)", systemImage: "text.bubble")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(note)
                                .font(.callout)
                                .textSelection(.enabled)
                                .accessibilityIdentifier("request-note")
                        }
                        .accessibilityElement(children: .combine)
                    } footer: {
                        Text("Written on the computer. It explains the request; the code and the command are what you approve.")
                    }
                }
                Section {
                    VStack(spacing: 4) {
                        Text("Code in your terminal").font(.caption).foregroundStyle(.secondary)
                        Text(request.code)
                            .font(.system(size: 34, weight: .semibold, design: .monospaced))
                            .accessibilityLabel(request.code.map(String.init).joined(separator: " "))
                        // Only this line ticks: a TimelineView around the whole list redrew every section once a second.
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in
                            let left = Int(request.expiresAt.timeIntervalSince(ctx.date).rounded(.down))
                            Text("\(request.host) · \(request.user) · \(left > 0 ? "expires in \(left) s" : "expired")")
                                .font(.footnote)
                                .foregroundStyle(left < 20 ? .red : .secondary)
                                .monospacedDigit()
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                if request.isUnknownKind {
                    Section {
                        Label("This request needs a newer version of KeyTap. Update the app, then run the command again.",
                              systemImage: "arrow.down.app")
                            .font(.callout)
                    }
                } else if request.isTest {
                    Section {
                        Label("Dry run — nothing is decrypted. It checks the computer, this phone, your PIN and the tap.",
                              systemImage: "checkmark.shield")
                            .font(.callout)
                    }
                } else if let ssh = request.ssh {
                    Section {
                        Label(ssh.isLogin ? "Sign in as \(ssh.login ?? "?")" : "SSH signature", systemImage: "terminal.fill")
                            .font(.callout.weight(.semibold))
                        if let name = ssh.keyName ?? ssh.keyFingerprint {
                            LabeledContent("Key") { Text(name).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle) }
                        }
                        if let host = ssh.hostKeyFingerprint {
                            LabeledContent("Server key") { Text(host).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle) }
                        }
                        commandRow
                    } footer: {
                        Text(ssh.isLogin
                             ? "Your YubiKey signs this one SSH login with its FIDO2 key. The key never leaves the YubiKey."
                             : "Your YubiKey signs with its FIDO2 SSH key. The key never leaves the YubiKey.")
                    }
                } else {
                    Section {
                        if let f = request.targetFile {
                            PathRow(symbol: "doc", path: f)
                        }
                        if !request.cwd.isEmpty {
                            PathRow(symbol: "folder", path: request.cwd)
                        }
                        commandRow
                        if request.files.count > 1 || request.identities.count > 1 {
                            LabeledContent("Files · YubiKeys", value: "\(request.files.count) · \(request.identities.map { String($0.serial) }.joined(separator: ", "))")
                                .font(.footnote)
                        }
                    }
                }
                if let error {
                    Section {
                        Label(error, systemImage: lastTry ? "exclamationmark.octagon.fill" : "exclamationmark.triangle")
                            .foregroundStyle(.red)
                            .font(lastTry ? .callout.weight(.semibold) : .callout)
                        if pinBlocked && !request.isSSH {
                            Button("Unblock the PIN with the PUK", systemImage: "lock.open") { showPUK = true }
                        }
                    }
                }
            }
            .listSectionSpacing(.compact)
            .contentMargins(.top, 8, for: .scrollContent)
            .safeAreaInset(edge: .bottom) { actions }
            .task(id: request.id) {
                expired = request.expiresAt <= .now
                guard !expired else { return }
                try? await Task.sleep(for: .seconds(request.expiresAt.timeIntervalSinceNow))
                guard !Task.isCancelled else { return }
                expired = true
                error = "This request expired."
            }
            .navigationTitle(request.isTest ? "Dry Run" : request.ssh.map { $0.isLogin ? "Approve SSH Login" : "Approve SSH Signature" } ?? "Approve Decryption")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if expired {
                        Button("Close") { model.dismissExpired() }
                    } else {
                        Button("Decline", role: .destructive) { Task { await decline() } }
                            .disabled(busy)
                            .accessibilityIdentifier("decline")
                    }
                }
            }
            .onAppear {
                pinFocused = !model.approvesInSoftware
                if picked == nil { picked = request.defaultKey ?? keys.first?.serial }
            }
            .sheet(isPresented: $showPUK) {
                PUKSheet(serial: picked, label: { request.label(of: $0) }) {
                    showPUK = false
                    pinBlocked = false
                    error = "PIN changed. Enter the new PIN and approve."
                }
                .environment(model)
            }
        }
    }

    /// The requesting command line, one line until tapped.
    private var commandRow: some View {
        Button {
            showCommand.toggle()
        } label: {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: "terminal").foregroundStyle(.secondary).frame(width: 22)
                Text(request.command)
                    .font(.caption.monospaced())
                    .lineLimit(showCommand ? nil : 1)
                    .truncationMode(.middle)
                    .foregroundStyle(.primary)
            }
        }
        .buttonStyle(.plain)
        .accessibilityHint(showCommand ? "Shows less" : "Shows the full command")
    }

    private var pinPrompt: String {
        let kind = request.isSSH ? "FIDO2 PIN" : "PIN"
        return pickedLabel.map { "\(kind) of \($0)" } ?? "YubiKey \(kind)"
    }

    /// Which key the PIN is for: the computer's list, its default preselected. A single key needs no menu.
    @ViewBuilder private var keyPicker: some View {
        HStack {
            if keys.count > 1 {
                Menu {
                    Picker("YubiKey", selection: Binding(get: { picked ?? 0 }, set: { picked = $0; error = nil; lastTry = false })) {
                        ForEach(keys, id: \.serial) { k in Text("\(k.label) · \(String(k.serial))").tag(k.serial) }
                    }
                } label: {
                    Label(pickedLabel ?? "Pick the YubiKey", systemImage: "key.horizontal")
                        .font(.callout.weight(.medium))
                }
                .accessibilityIdentifier("key-picker")
            } else if let l = pickedLabel {
                Label(l, systemImage: "key.horizontal").font(.callout.weight(.medium))
            }
            Spacer()
            Button("Not sure? Tap to identify") { Task { await identify() } }
                .font(.caption)
                .disabled(busy)
                .accessibilityIdentifier("identify")
        }
    }

    private func identify() async {
        busy = true
        defer { busy = false }
        do {
            if let s = try await model.identifyKey() {
                picked = s
                error = keys.contains { $0.serial == s } ? nil
                    : "\(request.label(of: s)) is not one of this computer's keys. It can still try, if the request is for it."
                pinFocused = true
            }
        } catch NFCError.cancelled {
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    /// SSH uses the YubiKey's FIDO2 PIN (4–63 characters, any), decryptions its PIV PIN (6–8 digits or letters).
    private var pinValid: Bool { request.isSSH ? (4...63).contains(pin.count) : (6...8).contains(pin.count) }

    /// PIN + approve, always on screen above the keyboard.
    private var actions: some View {
        VStack(spacing: 10) {
            if !model.approvesInSoftware && !model.isDemo {
                keyPicker
            }
            if !model.approvesInSoftware {
                SecureField(pinPrompt, text: $pin)
                    .keyboardType(request.isSSH ? .asciiCapable : .numberPad)
                    .textContentType(.oneTimeCode)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($pinFocused)
                    .padding(12)
                    .background(.background, in: .rect(cornerRadius: 12))
            }
            Button {
                Task { await approve() }
            } label: {
                HStack {
                    if busy { ProgressView().tint(.white) }
                    Label(model.isDemo ? "Approve (demo)" : model.useSoftwareKey ? "Approve (software test key)"
                          : request.isTest ? "Run with YubiKey" : request.isSSH ? "Sign with YubiKey" : "Approve with YubiKey",
                          systemImage: "key.radiowaves.forward")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(busy || expired || request.isUnknownKind || (!model.approvesInSoftware && !pinValid))
            .accessibilityIdentifier("approve")
            if !model.approvesInSoftware {
                Text(pickedLabel.map { "Then hold \($0) to the top of the iPhone. The PIN goes only to that key — another key gets no PIN." }
                     ?? "Then hold your YubiKey to the top of the iPhone. The PIN goes only to the key.")
                    .font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 10)
        .padding(.bottom, 6)
        .background(.bar)
    }

    private func approve() async {
        busy = true
        error = nil
        lastTry = false
        let p = pin
        pin = ""
        defer { busy = false }
        do {
            try await model.approve(pin: p, picked: picked)
        } catch NFCError.cancelled {
        } catch let TapError.otherKeyTapped(tapped, tappedLabel, _, pickedLabel) {
            // No PIN went anywhere. Switch the picker to the key that was tapped, ask for its PIN.
            picked = tapped
            error = "That was \(tappedLabel), not \(pickedLabel) — no PIN was sent. Enter the PIN of \(tappedLabel), or pick \(pickedLabel) again."
            pinFocused = true
        } catch PIVError.wrongPIN(let n) {
            lastTry = n == 1
            error = n == 1 ? "Wrong PIN — 1 try left on \(pickedLabel ?? "this key"). One more wrong PIN blocks it; then only the PUK unblocks it."
                : PIVError.wrongPIN(retriesLeft: n).errorDescription
            pinFocused = true
        } catch PIVError.pinBlocked {
            pinBlocked = true
            error = "The PIN of \(pickedLabel ?? "this YubiKey") is blocked. Unblock it with its PUK and set a new PIN."
        } catch CTAPError.wrongPIN(let n) {
            lastTry = n == 1
            error = n == 1 ? "Wrong FIDO2 PIN — 1 try left on \(pickedLabel ?? "this key"). One more blocks it, and a blocked FIDO2 PIN can only be fixed by resetting FIDO2, which deletes the SSH keys on it."
                : CTAPError.wrongPIN(retriesLeft: n).errorDescription
            pinFocused = true
        } catch CTAPError.pinBlocked {
            error = "The FIDO2 PIN of \(pickedLabel ?? "this YubiKey") is blocked. Only a FIDO2 reset fixes that, and a reset deletes the SSH keys on it — KeyTap never resets a key. Follow your recovery procedure, or use another of your keys."
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    private func decline() async {
        busy = true
        defer { busy = false }
        do { try await model.decline() } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}

/// A path on one line: the last component in full, the folder shortened from the start.
private struct PathRow: View {
    let symbol: String
    let path: String

    var body: some View {
        // Split the text as the command gave it: a relative path must not turn into an absolute-looking one.
        let trimmed = path.hasSuffix("/") && path.count > 1 ? String(path.dropLast()) : path
        let cut = trimmed.lastIndex(of: "/")
        let name = cut.map { String(trimmed[trimmed.index(after: $0)...]) } ?? trimmed
        let dir = cut.map { $0 == trimmed.startIndex ? "/" : String(trimmed[..<$0]) } ?? ""
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).font(.callout.monospaced()).lineLimit(1).truncationMode(.middle)
                Text(dir).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.head)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(path)
    }
}

/// PIN blocked → PUK + a new PIN, on the same key (checked by serial before the PUK is sent).
struct PUKSheet: View {
    @Environment(AppModel.self) private var model
    let serial: UInt32?
    let label: @Sendable (UInt32) -> String
    let done: () -> Void
    @State private var puk = ""
    @State private var newPIN = ""
    @State private var again = ""
    @State private var busy = false
    @State private var error: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("PUK", text: $puk).keyboardType(.asciiCapable).textContentType(.oneTimeCode)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                } footer: {
                    Text("The PUK of \(serial.map(label) ?? "your YubiKey") — 6 to 8 characters, set when the key was prepared. Three wrong PUKs block it for good; then the PIV keys on it can only be replaced, not recovered.")
                }
                Section {
                    SecureField("New PIN", text: $newPIN).keyboardType(.asciiCapable).textContentType(.oneTimeCode)
                    SecureField("New PIN again", text: $again).keyboardType(.asciiCapable).textContentType(.oneTimeCode)
                } footer: {
                    Text("6 to 8 characters. Goes only to the YubiKey; nothing is stored.")
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
                Section {
                    Button {
                        Task { await run() }
                    } label: {
                        HStack { Text("Unblock with YubiKey"); Spacer(); if busy { ProgressView() } }
                    }
                    .disabled(busy || !(6...8).contains(puk.count) || !(6...8).contains(newPIN.count) || newPIN != again)
                }
            }
            .navigationTitle("Unblock PIN")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }

    private func run() async {
        busy = true
        error = nil
        let (k, n) = (puk, newPIN)
        puk = ""
        defer { busy = false }
        do {
            try await model.unblockPIN(puk: k, newPIN: n, expect: serial, label: label)
            newPIN = ""
            again = ""
            done()
        } catch NFCError.cancelled {
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}
