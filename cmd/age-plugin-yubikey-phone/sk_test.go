package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sshStr(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }

func edBlob(pk ed25519.PublicKey, app string) []byte {
	return bytes.Join([][]byte{sshStr([]byte("sk-ssh-ed25519@openssh.com")), sshStr(pk), sshStr([]byte(app))}, nil)
}

// userauth builds the data ssh signs for a publickey login (RFC 4252 §7).
func userauth(user string, blob []byte) []byte {
	var b []byte
	b = append(b, sshStr(bytes.Repeat([]byte{7}, 32))...) // session id
	b = append(b, 50)
	b = append(b, sshStr([]byte(user))...)
	b = append(b, sshStr([]byte("ssh-connection"))...)
	b = append(b, sshStr([]byte("publickey"))...)
	b = append(b, 1)
	b = append(b, sshStr([]byte("sk-ssh-ed25519@openssh.com"))...)
	b = append(b, sshStr(blob)...)
	return b
}

// assert is what a YubiKey returns for getAssertion: a signature over rpIdHash ‖ flags ‖ counter ‖ clientDataHash.
func assertEd(sk ed25519.PrivateKey, app string, data []byte, flags uint8, counter uint32) []byte {
	a := sha256.Sum256([]byte(app))
	d := sha256.Sum256(data)
	msg := append(append(append([]byte{}, a[:]...), flags), binary.BigEndian.AppendUint32(nil, counter)...)
	return ed25519.Sign(sk, append(msg, d[:]...))
}

func TestParseSKRequest(t *testing.T) {
	in := "keytap-sk-v1\nalg 1\nflags 37\napplication ssh:deploy\nkey_handle " + hex.EncodeToString([]byte{1, 2, 3}) +
		"\ndata " + hex.EncodeToString([]byte("hello")) + "\n"
	q, err := parseSKRequest(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if q.alg != 1 || q.flags != 37 || q.application != "ssh:deploy" || !bytes.Equal(q.keyHandle, []byte{1, 2, 3}) || string(q.data) != "hello" {
		t.Fatalf("parsed %+v", q)
	}
	for _, bad := range []string{"", "other\n", "keytap-sk-v1\nalg 7\napplication ssh:\nkey_handle 01\n", "keytap-sk-v1\nalg 1\napplication web:x\nkey_handle 01\n"} {
		if _, err := parseSKRequest(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDescribeLoginAndVerify(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	blob := edBlob(pk, "ssh:deploy")
	data := userauth("deploy", blob)
	purpose, login, key, _ := describeSSHData(data)
	if purpose != "login" || login != "deploy" || key == nil || key.application != "ssh:deploy" {
		t.Fatalf("describe: %q %q %+v", purpose, login, key)
	}
	sig := assertEd(sk, "ssh:deploy", data, 0x05, 42)
	a := &SSHAnswer{Signature: base64.RawStdEncoding.EncodeToString(sig), Flags: 0x05, Counter: 42}
	if err := verifyAssertion(key, "ssh:deploy", data, a, sig); err != nil {
		t.Fatal(err)
	}
	// a different counter, flags or data must not verify
	for _, mod := range []func(a *SSHAnswer, d []byte) []byte{
		func(a *SSHAnswer, d []byte) []byte { a.Counter++; return d },
		func(a *SSHAnswer, d []byte) []byte { a.Flags = 0x01; return d },
		func(a *SSHAnswer, d []byte) []byte { return append(append([]byte{}, d...), 0) },
	} {
		b := *a
		d := mod(&b, data)
		if verifyAssertion(key, "ssh:deploy", d, &b, sig) == nil {
			t.Error("tampered assertion verified")
		}
	}
	if p, _, _, _ := describeSSHData([]byte("SSHSIG...")); p != "signature" {
		t.Errorf("non-login data described as %q", p)
	}
}

func TestVerifyECDSAAssertion(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) //nolint:staticcheck
	blob := bytes.Join([][]byte{sshStr([]byte("sk-ecdsa-sha2-nistp256@openssh.com")), sshStr([]byte("nistp256")), sshStr(q), sshStr([]byte("ssh:"))}, nil)
	k, ok := parseSKBlob(blob)
	if !ok {
		t.Fatal("blob not parsed")
	}
	data := []byte("data")
	ah, dh := sha256.Sum256([]byte("ssh:")), sha256.Sum256(data)
	msg := append(append(append([]byte{}, ah[:]...), 0x01), append(binary.BigEndian.AppendUint32(nil, 9), dh[:]...)...)
	d := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, d[:])
	if err := verifyAssertion(k, "ssh:", data, &SSHAnswer{Flags: 1, Counter: 9}, sig); err != nil {
		t.Fatal(err)
	}
}

func TestSignedMessageCoversSSH(t *testing.T) {
	a := &Answer{ID: "x", SSH: &SSHAnswer{Signature: "c2ln", Flags: 5, Counter: 3}}
	m := string(signedMessage([]byte("{}"), "n", a))
	if !strings.HasSuffix(m, "n\nssh c2ln 5 3\n") {
		t.Fatalf("signed message %q", m)
	}
}

func TestSSHOpts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYTAP_DIR", dir)
	if err := runSSHOpts(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("ssh-opts without a paired phone succeeded")
	}
	cfg := &Config{Listen: "10.0.0.1:8743", Devices: []Device{{Name: "phone"}}}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	prov := filepath.Join(dir, "keytap-sk.dylib")
	os.WriteFile(prov, []byte("x"), 0o644)
	t.Setenv("KEYTAP_SK_PROVIDER", prov)
	key := filepath.Join(dir, "id_ed25519_sk_test")
	os.WriteFile(key, []byte("stub"), 0o600)
	var out bytes.Buffer
	if err := runSSHOpts([]string{key}, &out); err != nil {
		t.Fatal(err)
	}
	want := "-o\nSecurityKeyProvider=" + prov + "\n-o\nIdentitiesOnly=yes\n-i\n" + key + "\n"
	if out.String() != want {
		t.Fatalf("ssh-opts printed %q", out.String())
	}
	if err := runSSHOpts([]string{filepath.Join(dir, "missing")}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing key file accepted")
	}
}

func TestDescribeHostBoundLogin(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	blob := edBlob(pk, "ssh:")
	var b []byte
	b = append(b, sshStr(bytes.Repeat([]byte{7}, 32))...)
	b = append(b, 50)
	b = append(b, sshStr([]byte("deploy"))...)
	b = append(b, sshStr([]byte("ssh-connection"))...)
	b = append(b, sshStr([]byte("publickey-hostbound-v00@openssh.com"))...)
	b = append(b, 1)
	b = append(b, sshStr([]byte("sk-ssh-ed25519@openssh.com"))...)
	b = append(b, sshStr(blob)...)
	b = append(b, sshStr([]byte("host key blob"))...)
	purpose, login, key, host := describeSSHData(b)
	if purpose != "login" || login != "deploy" || key == nil || string(host) != "host key blob" {
		t.Fatalf("describe: %q %q %v %q", purpose, login, key, host)
	}
}
