import SwiftUI

/// What KeyTap is, why it exists and why it is safe — inside the app, so it needs no website.
struct DocsView: View {
    var body: some View {
        List {
            Section {
                Text("KeyTap lets you approve a decryption or an SSH sign-in on your computer with the YubiKey in your pocket — by tapping it against your iPhone.")
            }
            DocSection(title: "The gap it closes", systemImage: "puzzlepiece.extension") {
                "Tools like age and sops can keep the decryption key on a YubiKey (age-plugin-yubikey): nothing on the computer can decrypt without the key, its PIN and a touch."
                "That breaks the moment the YubiKey and the computer are apart — you are travelling with your phone and the key, and work on the computer remotely. The usual workarounds all put a usable key back on a machine: a copied key file, a server that approves for you, a push button."
                "KeyTap turns the iPhone into a remote card reader for exactly these operations. The key agreement or the signature still happens on the YubiKey, which still asks for its PIN and a tap."
            }
            DocSection(title: "How it works", systemImage: "arrow.left.arrow.right") {
                "1. You decrypt on the computer as usual. The KeyTap bridge — an age plugin on the computer — receives the encrypted file key, which only your YubiKey can unwrap."
                "2. KeyTap shows the request in plain words: which command, which file, which computer, a short code that the computer's terminal shows too, and a note if whoever started it wrote one."
                "3. You pick the YubiKey you hold (the computer preselects the one you used last), enter its PIN and hold it to the phone. The phone reads the key's serial number first: a different key gets no PIN at all. The YubiKey performs the key agreement (PIV, P-256)."
                "4. The phone unwraps the 16-byte file key and sends only that back. The computer finishes decrypting."
            }
            DocSection(title: "SSH sign-ins", systemImage: "terminal") {
                "SSH keys that live on the YubiKey (ed25519-sk or ecdsa-sk, made with ssh-keygen and the key plugged in) work too. The bridge brings a small OpenSSH security key provider; ssh hands it the sign-in, and it appears here like a decryption."
                "You see the account you sign in as, the key, the server's key and the ssh command. Enter the YubiKey's FIDO2 PIN and hold the key to the phone: the YubiKey signs this one login with its FIDO2 key, the phone sends only the signature back."
            }
            DocSection(title: "Several YubiKeys", systemImage: "key.horizontal") {
                "Any of your YubiKeys answers — the everyday one, a spare, the one in the safe. The computer keeps the list and sends it with each request; this iPhone registers none, so adding or dropping a key is a change on the computer only."
                "One PIN, one tap. sops asks once per key a file is encrypted to and ssh tries one key after the other: KeyTap holds the tapped key for the whole command, skips the requests for the others and answers the right one in the same tap."
            }
            DocSection(title: "Several computers", systemImage: "desktopcomputer") {
                "Pair this iPhone with each computer you use — a laptop, a desktop at home, a workstation at the office. KeyTap asks all of them and shows each request with the computer's name. If another computer answers first, the request here closes by itself."
            }
            DocSection(title: "Why it is secure", systemImage: "lock.shield") {
                "Key, PIN and presence are still required. The private key never leaves the YubiKey; the PIN goes only to the YubiKey it was entered for — checked by serial number before anything is sent — and is never stored; the tap is the presence."
                "No server. KeyTap talks to one peer only: your own computer, directly over your network or your own VPN. There is no KeyTap service, no account, no cloud."
                "Notifications are optional and off by default. If you switch them on, your computer asks the KeyTap relay to wake this iPhone through Apple's push service; a notification says only what kind of request is waiting (a decryption, an SSH sign-in, a dry run) and when it expires — no computer, command, file or code — and the relay stores nothing. Without them, keep KeyTap open while you decrypt."
                "Pinned and paired. The phone trusts only the certificate it paired with; the computer trusts only this phone's key, created in the Secure Enclave, which signs every answer — bound to the exact request you saw and to a one-time nonce, so it cannot be replayed."
                "The computer only listens while a request waits for you, only on the address you chose, and each request expires after five minutes."
                "Compare the code. Someone who controls the computer could start a request of their own; that is why you see the command and the code before you approve."
            }
            DocSection(title: "What stays on this iPhone", systemImage: "iphone") {
                "For each paired computer its name, address, certificate fingerprint and pairing token, and the handle of the Secure Enclave key — in the keychain, this device only: never in iCloud, never in a backup. Nothing about your YubiKeys: their list comes with each request and is gone when it is answered."
                "Nothing is collected, nothing is sent anywhere else. No analytics, no crash reports, no third-party code."
            }
            DocSection(title: "What you need", systemImage: "checklist") {
                "A YubiKey 5 with NFC (or one you can plug into the iPhone) holding an age key made by age-plugin-yubikey."
                "A computer running age or sops with the KeyTap bridge (age-plugin-yubikey-phone). For SSH: OpenSSH 9.0 or later and an ed25519-sk key on the YubiKey."
                "The phone and the computer on the same network, or the phone on a VPN into it."
            }
            Section {
                Link("keytap.me — guide, security and privacy", destination: Links.website)
                NavigationLink("Legal — privacy, terms, imprint, licenses") { LegalView() }
                Text("KeyTap \(AppInfo.version)").foregroundStyle(.secondary)
                Text("YubiKey is a registered trademark of Yubico AB. KeyTap is an independent project and is not affiliated with, sponsored or endorsed by Yubico. Apple and iPhone are trademarks of Apple Inc.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("About KeyTap")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct DocSection: View {
    let title: String
    let systemImage: String
    let paragraphs: [String]

    init(title: String, systemImage: String, @ParagraphBuilder _ content: () -> [String]) {
        self.title = title
        self.systemImage = systemImage
        self.paragraphs = content()
    }

    var body: some View {
        Section {
            ForEach(paragraphs, id: \.self) { Text($0).font(.callout) }
        } header: {
            Label(title, systemImage: systemImage)
        }
    }
}

@resultBuilder
enum ParagraphBuilder {
    static func buildBlock(_ parts: String...) -> [String] { parts }
}
