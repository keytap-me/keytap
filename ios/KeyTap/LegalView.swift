import SwiftUI

/// Every legal topic in one place. The essentials are readable offline; the full documents are on
/// keytap.me (they open in Safari when tapped — the app itself only ever talks to your computer).
struct LegalView: View {
    var body: some View {
        List {
            Section {
                Label("KeyTap collects no personal data.", systemImage: "hand.raised.fill")
                    .font(.headline)
                Text("No accounts, no analytics, no tracking, no ads, no third-party code. The app talks only to the computer you paired it with. The computer's address, its certificate fingerprint, the pairing token and the Secure Enclave key handle stay in this iPhone's keychain — this device only, never in iCloud or a backup. Your YubiKey PIN goes only to the key and is never stored. Unpair or delete the app to remove everything.")
                    .font(.callout)
                Link(destination: Links.privacy) { Label("Full Privacy Policy", systemImage: "doc.text") }
            } header: {
                Text("Privacy")
            }

            Section {
                Text("KeyTap is free. Your use of the app is governed by Apple's standard Licensed Application End User License Agreement.")
                    .font(.callout)
                Link(destination: Links.eula) { Label("Terms of Use (Apple standard EULA)", systemImage: "doc.plaintext") }
            } header: {
                Text("Terms")
            }

            Section {
                Text("Published by Mirox Verwaltungs GmbH, Hamburg, Germany. Contact: support@keytap.me")
                    .font(.callout)
                    .textSelection(.enabled)
                Link(destination: Links.imprint) { Label("Imprint (Impressum)", systemImage: "building.2") }
                Link(destination: Links.support) { Label("Support", systemImage: "questionmark.circle") }
            } header: {
                Text("Provider")
            }

            Section {
                Text("The app uses only Apple's frameworks (SwiftUI, CryptoKit, CoreNFC, Security) and contains no third-party code.")
                    .font(.callout)
                Text("The KeyTap bridge for your computer is open source under MIT OR Apache-2.0.")
                    .font(.callout)
                Link(destination: Links.source) { Label("Bridge source code and licenses", systemImage: "chevron.left.forwardslash.chevron.right") }
            } header: {
                Text("Open source")
            }

            Section {
                Text("YubiKey is a registered trademark of Yubico AB. KeyTap is an independent project and is not affiliated with, sponsored or endorsed by Yubico. Apple and iPhone are trademarks of Apple Inc., registered in the U.S. and other countries.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Trademarks")
            }

            Section {
                LabeledContent("Version", value: AppInfo.version)
            }
        }
        .navigationTitle("Legal")
        .navigationBarTitleDisplayMode(.inline)
    }
}
