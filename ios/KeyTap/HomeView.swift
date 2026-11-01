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
                    .symbolEffect(.pulse, isActive: model.link == .notListening || model.link == .waiting)
                Text(title).font(.title3.weight(.semibold))
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
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
                        Button("Leave Demo") { model.leaveDemo() }
                            .font(.callout)
                    }
                    .padding(.horizontal, 24)
                }
                Text(model.isDemo ? "Demo — no computer, no YubiKey, nothing leaves this iPhone." : "Keep KeyTap open while you decrypt.")
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity)
            .padding(.bottom)
            .navigationTitle(model.isDemo ? "KeyTap Demo" : model.pairing?.name ?? "KeyTap")
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
        case .error: "Can't reach \(model.pairing?.name ?? "the workstation")"
        }
    }

    private var subtitle: String {
        if model.isDemo { return "This is what a decryption request from your computer looks like. Send one, then approve or decline it." }
        return switch model.link {
        case .unknown: ""
        case .waiting, .notListening: "Requests from \(model.pairing?.name ?? "your workstation") appear here when you decrypt."
        case .error(let e): e
        }
    }
}
