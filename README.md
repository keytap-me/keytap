# KeyTap bridge — `age-plugin-yubikey-phone`

Approve an `age` / `sops` decryption — or an SSH login with a FIDO2 key (`ed25519-sk`) — on your
computer with the YubiKey® in your pocket, by tapping it against your iPhone. This repository holds both sides: the computer side, a small age plugin
called the **KeyTap bridge** (`cmd/`), and the source of the free **KeyTap iPhone app** (`ios/`).
Website and full guide: **https://keytap.me**

```
sops / age ──stdio──> age-plugin-yubikey-phone ──HTTPS, only while a request waits──< KeyTap (iPhone) ──NFC──> YubiKey
                      (this repo, on your computer)    the phone connects out           PIN + key agreement on the key
```

## Why

`age-plugin-yubikey` keeps the decryption key on a YubiKey: nothing on the computer can decrypt
without the key, its PIN and a touch. That breaks when the key and the computer are apart — you
travel with your phone and the key, and work on the computer remotely. The usual workarounds put a
usable key back on a machine. KeyTap makes the iPhone a remote card reader for exactly one
operation; the YubiKey still does the key agreement and still asks for its PIN and a tap.

## Security model

- **Key, PIN and presence stay required.** The private key never leaves the YubiKey. The PIN is
  entered on the phone for a key you pick, goes only to that YubiKey (the phone reads the tapped key's
  serial first; a different key gets no PIN at all) and is never stored. The tap is the touch.
- **No server.** The phone talks to exactly one peer: your computer, directly over your network or
  your own VPN. There is no KeyTap service in the trust path, no account and no cloud. Notifications
  are optional and off by default; switched on, they are end-to-end encrypted (see below).
- **Pinned and paired.** `pair` creates a self-signed certificate; the phone pins its SHA-256. The
  phone creates a P-256 key in its Secure Enclave and registers it; every answer is signed with it,
  bound to the SHA-256 of the exact request bytes the phone displayed and to a one-time nonce.
- **Small exposure.** The bridge listens only while a decrypt waits, only on the address given to
  `pair --host`, and every request expires after 300 seconds (five minutes).
- **Only the file key travels back** (for SSH: only the signature, see SSH logins). The phone unwraps the 16-byte age file key and returns that,
  over TLS 1.3 to the pinned certificate. File contents never leave the computer.
- **Any of your YubiKeys, one prompt.** The phone stores nothing about your YubiKeys: the computer
  keeps the list (`keys.conf`, the identity file) and sends it with each request. `sops` starts the
  plugin once per recipient and ssh tries one key after the other, so one command is one *chain*: the
  phone holds the tapped key, the requests for other keys are answered "not here" without the phone,
  and the tapped key's request is answered in the same tap. One unwrap (or signature) per chain.
- **Limits.** Someone in control of your computer can start a decrypt of their own. That is why
  the phone shows the requesting command, its folder and a short code that your terminal shows too —
  compare before you approve.

The stanza handling follows `age-plugin-yubikey`'s `piv-p256` format: tag = SHA-256(compressed
recipient)[0..4]; shared secret = ECDH on the YubiKey (retired PIV slot); wrap key =
HKDF-SHA256(shared, epk ‖ recipient, "piv-p256"); file key = ChaCha20-Poly1305 with a zero nonce.

## Optional notifications

Off by default. A user can switch them on in the app; the phone then gives its computer its Apple
push token, and while a decrypt waits the bridge asks a relay to wake the phone. The relay
(`cmd/keytap-push-relay`, run by us at push.keytap.me; `pair --push-relay` points a bridge at your
own) forwards to Apple Push Notification service and stores nothing. It sees the push token, the
time, a random request id and ciphertext. A push carries no request details at all — no computer,
user, command, file, code or note — only that a request (or a dry run) is waiting and when it
expires, AES-256-GCM encrypted under a key only the bridge and the phone share (the request id is
authenticated data). The details are read in the app, over the direct connection. The notification disappears after the answer or the expiry.
iOS lets only an app on screen read NFC, so tapping the notification opens KeyTap on the request.

## Install

Prerequisites: [`age`](https://github.com/FiloSottile/age) and
[`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) with an identity on your key.

```sh
# macOS / Linux — downloads the latest release, verifies SHA256SUMS, installs to ~/.local/bin
curl -fsSL https://keytap.me/get | sh -s -- --shim

# Windows (PowerShell) — installs to %LOCALAPPDATA%\KeyTap\bin and puts it first on your PATH
& ([scriptblock]::Create((irm https://keytap.me/install.ps1))) -Shim

# or from source (Go 1.24+)
go install github.com/keytap-me/keytap/cmd/age-plugin-yubikey-phone@latest
```

Release binaries and `SHA256SUMS` are on the [releases page](https://github.com/keytap-me/keytap/releases),
with build provenance attestations for the downloaded archives
(`gh attestation verify age-plugin-yubikey-phone-<os>-<arch>.tar.gz --repo keytap-me/keytap`).

**The shim.** `--shim` / `-Shim` installs the bridge a second time under the name
`age-plugin-yubikey`, ahead of the real plugin on your PATH, so `age` and `sops` ask the phone.
Encryption and every other plugin command keep working: the bridge hands everything except
decryption to the real `age-plugin-yubikey`. Without the shim, point your own relay at the bridge.

## Use

```sh
age-plugin-yubikey-phone pair --host <IP of this computer>   # shows a QR code: scan it with the iPhone's camera
age-plugin-yubikey-phone test [--key LABEL]                   # dry run: PIN + tap + key agreement, nothing decrypted
sops -d secrets.enc.yaml                                      # approve on the phone (keep KeyTap open)
KEYTAP_NOTE="renewing the staging certs" sops -d secrets.enc.yaml   # with a note shown at the top of the request
age-plugin-yubikey-phone devices                              # paired phones, and the YubiKeys offered to them
age-plugin-yubikey-phone unpair "<phone name>"
```

`pair` draws its one-time `keytap://` link as a QR code in the terminal (bridge v0.5.2 or later; `--no-qr`
leaves it out) and prints the link as well, to paste into the app instead. The iPhone's camera offers
"Open in KeyTap", which lands on the pairing page.

The note is optional free text (up to 500 characters, control characters removed) from whoever
starts the decrypt, e.g. why it is needed. The phone shows it first, as the requester's own words. It explains; it authorises nothing — the code,
the command and the key still decide. `test --note "…"` sets it for a dry run.

State lives in `~/.secure/keytap/` (`KEYTAP_DIR` overrides): the bridge certificate, the paired
devices, the last key used (`last-key`, preselected on the phone) and a log of request metadata —
never a file key.

**Your YubiKeys.** The phone shows a key picker with the computer's list. Labels come from
`~/.secure/keytap/keys.conf` (`KEYTAP_KEYS`), one key per line, else from the comments
age-plugin-yubikey writes into the identity file (`~/.secure/age/yubikeys.agekey`, `KEYTAP_IDENTITIES`;
`test` takes each key's recipient from there):

```
# <serial> <label> [ssh <.pub of a FIDO2 key on it>]...
12345678 everyday ssh ~/.ssh/id_ed25519_sk_everyday.pub
23456789 spare    ssh ~/.ssh/id_ed25519_sk_spare.pub
```

Add or drop a line and the next request carries the new list; nothing changes on the phone.

**Several computers.** One iPhone can be paired with every computer you use (KeyTap 1.1 or later):
run `pair` on each and paste each link into the app (Settings ▸ Add a Computer). Each request shows
which computer asked.

## Canary: the whole chain, once

[`canary/canary.sh`](canary/canary.sh) runs everything above with the real things — this computer, your
iPhone, your YubiKey — and says what to do on the phone at each step: pair, the dry run, an `age`
decryption, a request you decline (it must fail), a `sops` decryption and an SSH login to a throwaway
sshd on 127.0.0.1. Run it after installing or updating, or to show someone how KeyTap works.

```sh
curl -fsSL https://raw.githubusercontent.com/keytap-me/keytap/main/canary/canary.sh -o canary.sh
sh canary.sh --pair          # everything, starting with pairing; without --pair it uses the paired phone
sh canary.sh decrypt ssh     # only these steps; --yes does not wait for Return between steps
```

Nothing real is touched: the files are made on the spot in a temp directory, encrypted to the recipients
your identity file names, and deleted at the end; the sshd accepts only your key and is stopped at the
end; no YubiKey slot is written. Steps whose tools are missing (sops, a FIDO2 key file) are skipped.

## SSH logins (FIDO2 keys on the YubiKey)

SSH keys that live on the YubiKey — `ssh-keygen -t ed25519-sk -O resident -O verify-required`, made
once with the key plugged in — can be approved on the phone too (bridge v0.4.0 and KeyTap 1.1 or
later). The macOS release ships `keytap-sk.dylib`, an OpenSSH security key provider, installed next
to the bridge (`~/.local/lib`). ssh hands it the signature; the bridge serves it to the phone like a
decryption, and the phone runs the FIDO2 assertion on the YubiKey over NFC with the PIN you enter
there (the YubiKey's FIDO2 PIN). The private key never leaves the YubiKey.

```sh
ssh $(age-plugin-yubikey-phone ssh-opts ~/.ssh/id_ed25519_sk) user@host
# = ssh -o SecurityKeyProvider=~/.local/lib/keytap-sk.dylib -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_sk user@host
```

- The phone shows the account you sign in as, the key, the server's host key and the ssh command
  (plus `KEYTAP_NOTE`, if set). The bridge checks the YubiKey's signature against the offered key
  before handing it to ssh.
- The key file (`id_ed25519_sk`) holds only the credential handle, no key material: copy it to any
  computer that should sign in this way. ssh-keygen needs the key plugged in to create it
  (`ssh-keygen -K` downloads resident keys).
- Keys made with `verify-required` make ssh ask for a PIN before signing: press Return there; the
  PIN is entered on the phone and goes only to the YubiKey (or answer it with `SSH_ASKPASS`).
- Tested with Homebrew's OpenSSH 10 (OpenSSH 9.0 or later: the provider speaks sk-api version 10). Use it with `ssh`
  directly, not through `ssh-add`: ssh-agent only loads providers from allowlisted paths.
  Creating keys and `ssh-keygen -K` through the phone are not supported; signing is.
- Several keys: pass one `-i` per key file. ssh tries them in order; with the phone holding the tapped
  YubiKey, the others fail at once and the right one signs in the same tap.

**The KeyTap agent** (bridge v0.5.0) is the other way in: an ssh-agent whose sk signatures come from
the phone — and, raced against it, from upstream agents (another computer's agent forwarded here) that
list the same key, i.e. have that YubiKey plugged in. The first valid signature wins; once the request
is open on the phone, the phone wins.

```sh
age-plugin-yubikey-phone agent -a ~/.ssh/keytap.sock [--keys DIR] [--upstream SOCK]...
ssh -o IdentityAgent=~/.ssh/keytap.sock -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_sk_everyday.pub user@host
```

It serves the keys named in `keys.conf` (and `--keys DIR`); the key handle is read from the private
key file next to each `.pub` (it holds only the credential id, useless without the YubiKey).

**For a race router** (ask several computers and the phone at once, the first answer wins), the bridge
can start the phone request speculatively and withdraw it: `hold --session ID` (age's phase 1 on
stdin), `status --session ID [--wait MS]` (pending 10 · engaged 11 · answered 12 · gone 13),
`withdraw --session ID [--force]` (7 = refused, the request is open on the phone), and
`--age-plugin=identity-v1 --session ID` to collect the result. With an explicit session the plugin
exits 0 answered · 3 withdrawn · 4 timed out · 5 declined · 6 not here. `version --json` reports
the protocol (2).

## The iPhone app (`ios/`)

The source of KeyTap as it is on the App Store: SwiftUI, Apple frameworks only (CryptoKit, CoreNFC,
Security), no third-party code, no analytics, no crash reporting.

| Path | What |
|---|---|
| `ios/KeyTap/` | the app |
| `ios/KeyTapNotify/` | the notification service extension: decrypts the detail-free notification summary on the phone |
| `ios/KeyTapCore/` | everything that is not UI — the piv-p256 unwrap, the PIV commands, the bridge client — as a Swift package with tests, plus `keytap-softphone`, a software phone for the Mac |
| `ios/Config/` | Info.plist, entitlements, privacy manifest settings |

Build it yourself (Xcode 16 or later):

```sh
cd ios/KeyTapCore && swift test                    # the protocol and crypto tests, no device needed
xcodebuild -project ios/KeyTap.xcodeproj -scheme KeyTap -configuration Release \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

To run it on your own iPhone, open `ios/KeyTap.xcodeproj`, choose your own team and bundle id, and
let Xcode sign it (NFC needs a paid developer account).

Every push is built here by [CI](.github/workflows/ci.yml), which also checks the built binary: the
only addresses it contains are keytap.me, this repository and Apple's licence page, and it embeds no
framework. The app shows its version and build in Settings ▸ About, and every build we upload to
the App Store has a tag here, `ios-v<version>-<build>` (e.g. `ios-v1.0.0-202610301517`), on the
exact source it was built from.

### What you can and cannot verify

You can read every line the app is built from, build it, and run your build instead of ours. What
you cannot do on iOS — for any app — is compare the App Store download with a build of your own:
Apple re-signs and encrypts each download for the device, so the bytes on your phone never match
what we uploaded, and iOS does not let you read them. A hash shown by the app would prove nothing
either, because a modified app could show any hash.

So KeyTap keeps what the app can do small, and that part does not depend on trusting our build:
the private key never leaves the YubiKey, so no app can copy it; every decrypt still needs the
physical key, its PIN and a tap; and the phone only ever sees the 16-byte file key (or the SSH
signature) of the one request in front of it, never your files. The computer side, where your files are, is this
repository's bridge, and that one you can verify: release binaries are built by GitHub Actions from
the tag, listed in `SHA256SUMS`, and carry build provenance attestations (see Install).

## Support, security reports

- Help: https://keytap.me/support · support@keytap.me
- Vulnerabilities: see [SECURITY.md](SECURITY.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option.
The licences cover the code. The KeyTap name and app icon are not licensed for other apps: if you
publish your own build, give it your own name and icon.

---

YubiKey is a registered trademark of Yubico AB. KeyTap is an independent project and is not
affiliated with, sponsored or endorsed by Yubico. Apple and iPhone are trademarks of Apple Inc.,
registered in the U.S. and other countries.
