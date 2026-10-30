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
	serial := fs.Uint("serial", 0, "which registered YubiKey to test (default: the first)")
	note := fs.String("note", os.Getenv("KEYTAP_NOTE"), "a short note shown on the phone (default: $KEYTAP_NOTE)")
	fs.Parse(args)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var key *YubiKey
	for _, d := range cfg.Devices {
		for i := range d.Keys {
			if key == nil && (*serial == 0 || d.Keys[i].Serial == uint32(*serial)) {
				key = &d.Keys[i]
			}
		}
	}
	if key == nil {
		return fmt.Errorf("no registered YubiKey to test; pair the phone first (`age-plugin-yubikey-phone pair --host IP`)")
	}

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
			Serial: key.Serial, Slot: key.Slot, Tag: key.tag(),
			EPK: base64.RawStdEncoding.EncodeToString(epk),
		},
		Identities: []Identity{{Serial: key.Serial, Slot: key.Slot, Tag: key.tag()}},
		Files:      []File{},
	}
	fmt.Printf("Testing YubiKey %d (slot %#x) through the phone.\n", key.Serial, key.Slot)
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
	if _, err := askPhone(nil, cfg, req, check); err != nil {
		return err
	}
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
