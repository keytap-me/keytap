package main

// `age-plugin-yubikey-phone test` — the dry run. It exercises everything a real decrypt uses
// (this bridge, the network path, the phone, its Secure Enclave signature, the YubiKey's PIN,
// touch and key agreement) without a file key existing anywhere: the bridge makes an ephemeral
// key, the phone runs the ECDH on the YubiKey, and both sides derive the same wrap key, which the
// phone proves with an HMAC instead of returning anything.

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

const probeLabel = "keytap-probe-v1"

func runTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	which := fs.String("key", "", "which YubiKey to test: label or serial (default: the last one used, else the first)")
	serial := fs.Uint("serial", 0, "same as --key SERIAL")
	note := fs.String("note", os.Getenv("KEYTAP_NOTE"), "a short note shown on the phone (default: $KEYTAP_NOTE)")
	fs.Parse(args)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if *serial != 0 && *which == "" {
		*which = fmt.Sprint(*serial)
	}
	var usable []keyEntry
	for _, k := range knownKeys() {
		if len(k.Recipient) == 33 && k.Slot != 0 {
			usable = append(usable, k)
		}
	}
	if len(usable) == 0 {
		return fmt.Errorf("no YubiKey with a known age recipient: %s needs age-plugin-yubikey's comments (Serial, Recipient) above each identity", identityFilePath())
	}
	var key *keyEntry
	for i := range usable {
		k := &usable[i]
		if (*which == "" && k.Serial == lastKey()) || (*which != "" && (k.Label == *which || fmt.Sprint(k.Serial) == *which)) {
			key = k
			break
		}
	}
	if key == nil && *which == "" {
		key = &usable[0]
	}
	if key == nil {
		return fmt.Errorf("no YubiKey %q in %s", *which, identityFilePath())
	}
	tag := func() string {
		sum := sha256.Sum256(key.Recipient)
		return base64.RawStdEncoding.EncodeToString(sum[:4])
	}()

	pub, err := ecdh.P256().NewPublicKey(decompressP256(key.Recipient))
	if err != nil {
		return fmt.Errorf("registered recipient is not a P-256 point: %w", err)
	}
	esk, _ := ecdh.P256().GenerateKey(rand.Reader)
	shared, err := esk.ECDH(pub)
	if err != nil {
		return err
	}
	epk := compressP256(esk.PublicKey().Bytes())
	wrapKey, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, epk...), key.Recipient...), "piv-p256", 32)
	if err != nil {
		return err
	}

	req := &Request{
		Note:    cleanNote(*note),
		Version: protoVersion,
		Kind:    "test",
		Probe: &Probe{
			Serial: key.Serial, Slot: key.Slot, Tag: tag,
			EPK: base64.RawStdEncoding.EncodeToString(epk),
		},
		Identities: []Identity{{Serial: key.Serial, Slot: key.Slot, Tag: tag}},
		Files:      []File{},
		Keys:       []KeyInfo{{Serial: key.Serial, Label: keyLabel(knownKeys(), key.Serial)}},
		Default:    key.Serial,
	}
	fmt.Printf("Testing %s (YubiKey %d, slot %#x) through the phone.\n", keyLabel(knownKeys(), key.Serial), key.Serial, key.Slot)
	// The proof is checked inside the request, so the phone learns the verdict too.
	check := func(a *Answer) error {
		mac := hmac.New(sha256.New, wrapKey)
		mac.Write([]byte(probeLabel))
		mac.Write([]byte(req.Nonce))
		got, err := b64any(a.Proof)
		if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
			return fmt.Errorf("the YubiKey's key agreement did not produce the expected secret (wrong key or slot?)")
		}
		return nil
	}
	if _, err := askPhone(func(m string) { fmt.Println(m) }, cfg, req, check); err != nil {
		return err
	}
	setLastKey(key.Serial)
	fmt.Println("✓ Dry run passed: phone reachable, answer signed by the paired phone, YubiKey PIN + tap + key agreement work.")
	fmt.Println("  Real decrypts will work the same way.")
	return nil
}

// compressP256 turns an uncompressed SEC1 point (0x04 ‖ X ‖ Y) into its compressed form.
func compressP256(u []byte) []byte {
	out := make([]byte, 33)
	out[0] = 2 | u[64]&1
	copy(out[1:], u[1:33])
	return out
}

// decompressP256 returns the uncompressed SEC1 point, or nil if b is not a compressed P-256 point.
func decompressP256(b []byte) []byte {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	if x == nil {
		return nil
	}
	return elliptic.Marshal(elliptic.P256(), x, y) //nolint:staticcheck // SEC1 encoding for crypto/ecdh
}
