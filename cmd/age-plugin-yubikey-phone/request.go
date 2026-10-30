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

type Request struct {
	Version    int        `json:"version"`
	Kind       string     `json:"kind,omitempty"` // "" = decrypt, "test" = dry run
	Probe      *Probe     `json:"probe,omitempty"`
	ID         string     `json:"id"`
	Code       string     `json:"code"` // shown in the terminal AND on the phone; the user compares
	Nonce      string     `json:"nonce"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Host       string     `json:"host"`
	User       string     `json:"user"`
	Command    string     `json:"command"` // the process that asked for the decrypt (sops / age …)
	Cwd        string     `json:"cwd"`
	Identities []Identity `json:"identities"`
	Files      []File     `json:"files"`
}

type Result struct {
	Index   int    `json:"index"`
	FileKey string `json:"file_key,omitempty"` // base64, 16 bytes
	Error   string `json:"error,omitempty"`
}

type Answer struct {
	ID        string   `json:"id"`
	Declined  bool     `json:"declined"`
	Results   []Result `json:"results"`
	Proof     string   `json:"proof,omitempty"` // dry run: base64 HMAC-SHA256(wrap key, "keytap-probe-v1" ‖ nonce)
	Signature string   `json:"signature"`       // base64 DER ECDSA-P256-SHA256 over signedMessage
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
	if a.Proof != "" {
		b.WriteString("proof " + a.Proof + "\n")
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
