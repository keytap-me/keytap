package main

// The request the phone fetches and the answer it posts back.
//
// The answer is signed by the phone's Secure Enclave key over a message that binds it to the
// exact request bytes the phone displayed (their SHA-256) and to the request's nonce, so a
// recorded answer cannot be replayed against a later request and an answer cannot be attached
// to content the user never saw.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

type Identity struct {
	Serial uint32 `json:"serial"`
	Slot   uint8  `json:"slot"` // PIV retired slot key reference, 0x82…0x95
	Tag    string `json:"tag"`  // base64, 4 bytes: SHA-256(compressed recipient)[0:4]
}

type PivStanza struct {
	StanzaIndex int    `json:"stanza_index"`
	Tag         string `json:"tag"`  // base64, 4 bytes
	EPK         string `json:"epk"`  // base64, 33 bytes SEC1 compressed
	Body        string `json:"body"` // base64, 32 bytes ChaCha20-Poly1305(file key)
}

type File struct {
	Index   int         `json:"index"`
	Stanzas []PivStanza `json:"stanzas"`
}

// Probe is the dry run (`age-plugin-yubikey-phone test`): an ephemeral key agreement against a
// registered YubiKey. The phone runs the real PIN + tap + ECDH and answers with an HMAC under
// the derived wrap key, so the whole chain is proven without any file key existing.
type Probe struct {
	Serial uint32 `json:"serial"`
	Slot   uint8  `json:"slot"`
	Tag    string `json:"tag"`
	EPK    string `json:"epk"` // base64, 33 bytes SEC1 compressed
}

// SSHSign is an OpenSSH FIDO2 signature (an ed25519-sk / ecdsa-sk key on the YubiKey, e.g. an ssh login):
// the phone runs CTAP2 getAssertion on the YubiKey's FIDO applet over NFC with these values and the PIN the
// user enters (user verification), and returns the authenticator's signature, flags and counter.
type SSHSign struct {
	Application      string `json:"application"`      // the FIDO rpId, e.g. "ssh:" or "ssh:deploy"
	CredentialID     string `json:"credential_id"`    // base64, the key handle from the ssh key file
	ClientDataHash   string `json:"client_data_hash"` // base64, SHA-256 of the data ssh signs
	Algorithm        string `json:"algorithm"`        // "ed25519" | "es256"
	UserPresence     bool   `json:"user_presence"`
	UserVerification bool   `json:"user_verification"`              // the key was made with verify-required
	KeySerial        uint32 `json:"key_serial,omitempty"`           // the YubiKey holding this credential, if the computer knows it (keys.conf)
	Purpose          string `json:"purpose"`                        // "login" (ssh user authentication) | "signature" (anything else)
	Login            string `json:"login,omitempty"`                // the remote user name of a login
	KeyFingerprint   string `json:"key_fingerprint,omitempty"`      // SHA256:… of the public key ssh offers
	KeyName          string `json:"key_name,omitempty"`             // the matching local .pub file or its comment
	HostKey          string `json:"host_key_fingerprint,omitempty"` // SHA256:… of the server's host key (host-bound login)
}

// KeyInfo is one YubiKey the computer knows (its keys.conf / identity file): what the phone offers in its
// key picker. Public facts only; the phone stores none of it.
type KeyInfo struct {
	Serial uint32 `json:"serial"`
	Label  string `json:"label"`
}

type Request struct {
	Version    int        `json:"version"`
	Keys       []KeyInfo  `json:"keys,omitempty"`      // the computer's YubiKeys, for the phone's picker
	Default    uint32     `json:"default,omitempty"`   // the key to preselect (the last one used here)
	Continues  string     `json:"continues,omitempty"` // the id of the request this one follows in the same tap (a chain)
	Kind       string     `json:"kind,omitempty"`      // "" = decrypt, "test" = dry run, "ssh" = OpenSSH FIDO2 signature
	Probe      *Probe     `json:"probe,omitempty"`
	SSH        *SSHSign   `json:"ssh,omitempty"`
	ID         string     `json:"id"`
	Code       string     `json:"code"` // shown in the terminal AND on the phone; the user compares
	Nonce      string     `json:"nonce"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Host       string     `json:"host"`
	User       string     `json:"user"`
	Command    string     `json:"command"` // the process that asked for the decrypt (sops / age …)
	Cwd        string     `json:"cwd"`
	Note       string     `json:"note,omitempty"` // free text from whoever started the decrypt (KEYTAP_NOTE); not verified
	Identities []Identity `json:"identities"`
	Files      []File     `json:"files"`
}

type Result struct {
	Index   int    `json:"index"`
	FileKey string `json:"file_key,omitempty"` // base64, 16 bytes
	Error   string `json:"error,omitempty"`
}

// SSHAnswer is the YubiKey's CTAP2 assertion for an SSHSign request.
type SSHAnswer struct {
	Signature string `json:"signature"` // base64: 64 bytes Ed25519, or DER ECDSA for es256
	Flags     uint8  `json:"flags"`     // authenticator data flags (UP 0x01, UV 0x04)
	Counter   uint32 `json:"counter"`   // signature counter
}

// Held: the phone has the tapped YubiKey (this serial) in an open session, but this request is not for
// it. The phone keeps the session open and waits for the next request of the chain (Continues).
type Held struct {
	Serial uint32 `json:"serial"`
}

type Answer struct {
	ID        string     `json:"id"`
	Declined  bool       `json:"declined"`
	Held      *Held      `json:"held,omitempty"`
	Results   []Result   `json:"results"`
	SSH       *SSHAnswer `json:"ssh,omitempty"`
	Proof     string     `json:"proof,omitempty"` // dry run: base64 HMAC-SHA256(wrap key, "keytap-probe-v1" ‖ nonce)
	Signature string     `json:"signature"`       // base64 DER ECDSA-P256-SHA256 over signedMessage
}

// signedMessage is the canonical byte string the phone signs. Keep it in lockstep with
// KeyTapCore/Answer.swift.
func signedMessage(requestBytes []byte, nonce string, a *Answer) []byte {
	sum := sha256.Sum256(requestBytes)
	var b strings.Builder
	b.WriteString("keytap-answer-v1\n")
	b.WriteString(hex.EncodeToString(sum[:]))
	b.WriteString("\n")
	b.WriteString(nonce)
	b.WriteString("\n")
	if a.Declined {
		b.WriteString("declined\n")
		return []byte(b.String())
	}
	if a.Held != nil {
		fmt.Fprintf(&b, "held %d\n", a.Held.Serial)
		return []byte(b.String())
	}
	if a.Proof != "" {
		b.WriteString("proof " + a.Proof + "\n")
	}
	if a.SSH != nil {
		fmt.Fprintf(&b, "ssh %s %d %d\n", a.SSH.Signature, a.SSH.Flags, a.SSH.Counter)
	}
	rs := append([]Result(nil), a.Results...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Index < rs[j].Index })
	for _, r := range rs {
		if r.FileKey != "" {
			fmt.Fprintf(&b, "%d %s\n", r.Index, r.FileKey)
		} else {
			fmt.Fprintf(&b, "%d !\n", r.Index)
		}
	}
	return []byte(b.String())
}

// deviceMessage is what the phone signs to change its notification settings.
// Keep in lockstep with KeyTapCore (BridgeClient.updateDevice).
func deviceMessage(p *pushSettings) []byte {
	if p == nil {
		return []byte("keytap-device-v1\npush off\n")
	}
	return []byte("keytap-device-v1\npush " + strings.ToLower(p.Token) + " " + p.Env + "\n")
}

func verifySigned(dev *Device, msg []byte, signature string) error {
	x, y := elliptic.Unmarshal(elliptic.P256(), dev.PublicKey) //nolint:staticcheck
	if x == nil {
		return errors.New("device public key is not a P-256 point")
	}
	sig, err := b64any(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

func verifyAnswer(dev *Device, requestBytes []byte, nonce string, a *Answer) error {
	x, y := elliptic.Unmarshal(elliptic.P256(), dev.PublicKey) //nolint:staticcheck // X9.63 point from the Secure Enclave
	if x == nil {
		return errors.New("device public key is not a P-256 point")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
	sig, err := b64any(a.Signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	digest := sha256.Sum256(signedMessage(requestBytes, nonce, a))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("answer signature does not verify against the paired device key")
	}
	return nil
}

// displayCode turns the request id into six characters a human can compare at a glance.
func displayCode(id []byte) string {
	sum := sha256.Sum256(id)
	c := base32.StdEncoding.EncodeToString(sum[:])[:6]
	return c[:3] + "-" + c[3:]
}

// The note: a short free-text line from whoever started the decrypt, e.g. why it is needed. Set KEYTAP_NOTE in the environment of sops / age
// (age starts the plugin with that environment); `test --note` sets it for a dry run. It is shown on
// the phone above everything else (never in a notification), labelled as the requester's own words: it explains, it does not
// authorise anything — the code, the command and the key still decide.
const maxNote = 500 // runes

// cleanNote drops control characters (keeping single line breaks, at most 4 lines), trims, and caps
// the length.
func cleanNote(s string) string {
	var b strings.Builder
	lines := 0
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '\n':
			if lines < 3 {
				b.WriteRune('\n')
			} else {
				b.WriteRune(' ')
			}
			lines++
		case r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			// control, line/paragraph separators, bidi overrides (they can make text read differently)
		default:
			b.WriteRune(r)
		}
	}
	return truncateRunes(strings.TrimSpace(b.String()), maxNote)
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-1])) + "…"
}
