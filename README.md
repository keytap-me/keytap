# KeyTap bridge — `age-plugin-yubikey-phone`

Approve an `age` / `sops` decryption on your computer with the YubiKey® in your pocket, by tapping
it against your iPhone. This repository holds the computer side: a small age plugin, the **KeyTap
bridge**. The iPhone side is the free KeyTap app. Website and full guide: **https://keytap.me**

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
  entered on the phone, goes only to the YubiKey (PIV VERIFY) and is never stored. The tap is the touch.
- **No server.** The phone talks to exactly one peer: your computer, directly over your network or
  your own VPN. There is no KeyTap service in the trust path, no account and no cloud. Notifications
  are optional and off by default; switched on, they are end-to-end encrypted (see below).
- **Pinned and paired.** `pair` creates a self-signed certificate; the phone pins its SHA-256. The
  phone creates a P-256 key in its Secure Enclave and registers it; every answer is signed with it,
  bound to the SHA-256 of the exact request bytes the phone displayed and to a one-time nonce.
- **Small exposure.** The bridge listens only while a decrypt waits, only on the address given to
  `pair --host`, and every request expires after 300 seconds (five minutes).
- **Only the file key travels back.** The phone unwraps the 16-byte age file key and returns that,
  over TLS 1.3 to the pinned certificate. File contents never leave the computer.
- **Registered keys only.** Pairing registers the YubiKeys you tap. `sops` starts the plugin once
  per recipient; requests for keys that are not registered are answered "not here" at once, so a
  file sealed to several YubiKeys still means one prompt.
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
age-plugin-yubikey-phone pair --host <IP of this computer>   # prints a keytap:// link: paste it into the app,
                                                              # tap your YubiKey(s) to register them
age-plugin-yubikey-phone test                                 # dry run: PIN + tap + key agreement, nothing decrypted
sops -d secrets.enc.yaml                                      # approve on the phone (keep KeyTap open)
KEYTAP_NOTE="renewing the staging certs" sops -d secrets.enc.yaml   # with a note shown at the top of the request
age-plugin-yubikey-phone devices                              # paired phones and their YubiKeys
age-plugin-yubikey-phone unpair "<phone name>"
```

The note is optional free text (up to 500 characters, control characters removed) from whoever
starts the decrypt, e.g. why it is needed. The phone shows it first, as the requester's own words. It explains; it authorises nothing — the code,
the command and the key still decide. `test --note "…"` sets it for a dry run.

State lives in `~/.secure/keytap/` (`KEYTAP_DIR` overrides): the bridge certificate, the paired
devices and a log of request metadata — never a file key.

## Support, security reports

- Help: https://keytap.me/support · support@keytap.me
- Vulnerabilities: see [SECURITY.md](SECURITY.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option.

---

YubiKey is a registered trademark of Yubico AB. KeyTap is an independent project and is not
affiliated with, sponsored or endorsed by Yubico. Apple and iPhone are trademarks of Apple Inc.,
registered in the U.S. and other countries.
