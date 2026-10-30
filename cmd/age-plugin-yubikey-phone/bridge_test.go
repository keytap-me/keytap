package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestStanzaRoundTrip(t *testing.T) {
	for _, n := range []int{0, 16, 32, 47, 48, 49, 96, 200} {
		body := make([]byte, n)
		rand.Read(body)
		var buf bytes.Buffer
		if err := writeStanza(&buf, "recipient-stanza", []string{"0", "piv-p256", "a", "b"}, body); err != nil {
			t.Fatal(err)
		}
		s, err := readStanza(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if s.Tag != "recipient-stanza" || len(s.Args) != 4 || !bytes.Equal(s.Body, body) {
			t.Fatalf("n=%d: mismatch", n)
		}
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	data := []byte{0x4e, 0x61, 0xbc, 0x00, 0x82, 1, 2, 3, 4} // serial 12345678 LE, retired slot 1
	s := bech32Encode(identityHRP, data)
	id, ok := parseIdentity(stringsToUpper(s))
	if !ok || id.Serial != 12345678 || id.Slot != 0x82 || id.Tag != base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3, 4}) {
		t.Fatalf("got %+v ok=%v", id, ok)
	}
}

func TestRecipientDecodes(t *testing.T) {
	hrp, data, err := bech32Decode("age1yubikey1qgarnds7s09l5vm5xgqf7k70ltzddsqtwwkt7lyvs6zmjgs9xm4dss5266r")
	if err != nil || hrp != "age1yubikey" || len(data) != 33 || (data[0] != 2 && data[0] != 3) {
		t.Fatalf("hrp=%q len=%d err=%v", hrp, len(data), err)
	}
}

func TestAnswerSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dev := &Device{PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y)}
	reqBytes := []byte(`{"id":"x"}`)
	a := &Answer{ID: "x", Results: []Result{{Index: 1, FileKey: "AAAA"}, {Index: 0, Error: "nope"}}}
	d := sha256.Sum256(signedMessage(reqBytes, "n", a))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
	a.Signature = base64.StdEncoding.EncodeToString(sig)
	if err := verifyAnswer(dev, reqBytes, "n", a); err != nil {
		t.Fatal(err)
	}
	if err := verifyAnswer(dev, reqBytes, "other-nonce", a); err == nil {
		t.Fatal("replay with another nonce verified")
	}
	if err := verifyAnswer(dev, []byte(`{"id":"y"}`), "n", a); err == nil {
		t.Fatal("answer verified against different request bytes")
	}
}

func stringsToUpper(s string) string { return string(bytes.ToUpper([]byte(s))) }
