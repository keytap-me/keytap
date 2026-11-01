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
    @FocusState private var pinFocused: Bool

    var body: some View {
        NavigationStack {
            TimelineView(.periodic(from: .now, by: 1)) { ctx in
                let left = Int(request.expiresAt.timeIntervalSince(ctx.date).rounded(.down))
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
                            Text("\(request.host) · \(request.user) · \(left > 0 ? "expires in \(left) s" : "expired")")
                                .font(.footnote)
                                .foregroundStyle(left < 20 ? .red : .secondary)
                                .monospacedDigit()
                        }
                        .frame(maxWidth: .infinity)
                    }
                    if request.isTest {
                        Section {
                            Label("Dry run — nothing is decrypted. It checks the computer, this phone, your PIN and the tap.",
                                  systemImage: "checkmark.shield")
                                .font(.callout)
                        }
                    } else {
                        Section {
                            if let f = request.targetFile {
                                PathRow(symbol: "doc", path: f)
                            }
                            if !request.cwd.isEmpty {
                                PathRow(symbol: "folder", path: request.cwd)
                            }
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
                            if request.files.count > 1 || request.identities.count > 1 {
                                LabeledContent("Files · YubiKeys", value: "\(request.files.count) · \(request.identities.map { String($0.serial) }.joined(separator: ", "))")
                                    .font(.footnote)
                            }
                        }
                    }
                    if let error {
                        Section { Text(error).foregroundStyle(.red).font(.callout) }
                    }
                }
                .listSectionSpacing(.compact)
                .contentMargins(.top, 8, for: .scrollContent)
                .safeAreaInset(edge: .bottom) { actions(left: left) }
                .onChange(of: left <= 0) { _, expired in if expired { error = "This request expired." } }
            }
            .navigationTitle(request.isTest ? "Dry Run" : "Approve Decryption")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if request.expiresAt < .now {
                        Button("Close") { model.dismissExpired() }
                    } else {
                        Button("Decline", role: .destructive) { Task { await decline() } }
                            .disabled(busy)
                            .accessibilityIdentifier("decline")
                    }
                }
            }
            .onAppear { pinFocused = !model.approvesInSoftware }
        }
    }

    /// PIN + approve, always on screen above the keyboard.
    private func actions(left: Int) -> some View {
        VStack(spacing: 10) {
            if !model.approvesInSoftware {
                SecureField("YubiKey PIN", text: $pin)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
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
                          : request.isTest ? "Run with YubiKey" : "Approve with YubiKey",
                          systemImage: "key.radiowaves.forward")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(busy || left <= 0 || (!model.approvesInSoftware && !(6...8).contains(pin.count)))
            .accessibilityIdentifier("approve")
            if !model.approvesInSoftware {
                Text("Then hold your YubiKey to the top of the iPhone. The PIN goes only to the key.")
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
        let p = pin
        pin = ""
        defer { busy = false }
        do {
            try await model.approve(pin: p)
        } catch NFCError.cancelled {
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
