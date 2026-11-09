import KeyTapCore
import SwiftUI

struct HomeView: View {
    @Environment(AppModel.self) private var model
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Spacer()
                Image(systemName: symbol)
                    .font(.system(size: 64, weight: .light))
                    .foregroundStyle(.tint)
                    // Pulses while the first contact is being made. Not in the resting state: an
                    // animation that never ends redraws the screen 60 times a second for hours.
                    .symbolEffect(.pulse, isActive: model.link == .unknown)
                Text(title).font(.title3.weight(.semibold))
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                if !model.isDemo && model.pairings.count > 1 {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(model.pairings) { p in
                            HStack {
                                Image(systemName: "desktopcomputer").foregroundStyle(.secondary)
                                Text(p.name)
                                Spacer()
                                Text(status(p)).font(.footnote).foregroundStyle(statusIsProblem(p) ? .red : .secondary)
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                    .padding(14)
                    .background(.fill.tertiary, in: .rect(cornerRadius: 12))
                    .padding(.horizontal, 24)
                }
                if let n = model.notice, !model.isDemo {
                    Label(n, systemImage: "info.circle")
                        .font(.footnote)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.fill.tertiary, in: .rect(cornerRadius: 12))
                        .padding(.horizontal, 24)
                        .onTapGesture { model.notice = nil }
                        .task(id: n) { try? await Task.sleep(for: .seconds(20)); if model.notice == n { model.notice = nil } }
                }
                Spacer()
                if model.isDemo {
                    VStack(spacing: 10) {
                        if let r = model.demoResult {
                            Label(r, systemImage: "checkmark.seal")
                                .font(.callout)
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(.fill.tertiary, in: .rect(cornerRadius: 12))
                        }
                        Button("Send a Demo Request", systemImage: "arrow.down.message") { model.sendDemoRequest() }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            .accessibilityIdentifier("demo-request")
                        Button("Send a Demo SSH Login", systemImage: "terminal") { Task { await model.sendDemoSSHRequest() } }
                            .buttonStyle(.bordered)
                            .controlSize(.large)
                            .accessibilityIdentifier("demo-ssh-request")
                        Button("Leave Demo") { model.leaveDemo() }
                            .font(.callout)
                    }
                    .padding(.horizontal, 24)
                }
                Text(model.isDemo ? "Demo — no computer, no YubiKey, nothing leaves this iPhone." : "Keep KeyTap open while you decrypt or sign in.")
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity)
            .padding(.bottom)
            .navigationTitle(model.isDemo ? "KeyTap Demo" : model.pairings.count == 1 ? model.pairings[0].name : "KeyTap")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Settings", systemImage: "gearshape") { showSettings = true }
            }
            .sheet(isPresented: $showSettings) { SettingsView() }
        }
    }

    private var symbol: String {
        switch model.link {
        case .error: "exclamationmark.triangle"
        default: "desktopcomputer"
        }
    }

    private var title: String {
        if model.isDemo { return "Demo" }
        return switch model.link {
        case .unknown: "Connecting…"
        case .waiting, .notListening: "Ready"
        case .error: model.pairings.count == 1 ? "Can't reach \(model.pairings[0].name)" : "Can't reach your computers"
        }
    }

    private func status(_ p: Pairing) -> String {
        switch model.links[p.id] ?? .unknown {
        case .unknown: "Connecting…"
        case .waiting, .notListening: "Ready"
        case .error: "Not reachable"
        }
    }

    private func statusIsProblem(_ p: Pairing) -> Bool {
        if case .error = model.links[p.id] ?? .unknown { true } else { false }
    }

    private var computers: String {
        switch model.pairings.count {
        case 0: "your workstation"
        case 1: model.pairings[0].name
        default: "your computers"
        }
    }

    private var subtitle: String {
        if model.isDemo { return "This is what a request from your computer looks like: a decryption, or an SSH sign-in. Send one, then approve or decline it." }
        return switch model.link {
        case .unknown: ""
        case .waiting, .notListening: "Requests from \(computers) appear here when you decrypt or sign in with SSH."
        case .error(let e): e
        }
    }
}
