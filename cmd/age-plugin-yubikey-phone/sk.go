package main

// OpenSSH FIDO2 keys (ed25519-sk / ecdsa-sk, e.g. `ssh-keygen -t ed25519-sk -O resident -O verify-required`)
// approved on the phone. OpenSSH hands a signature to a "security key provider", a shared library
// (keytap-sk.dylib, provider/ in the source). Ours starts this program as
//
//	age-plugin-yubikey-phone sk-sign        (request on stdin, answer on stdout, both line based)
//
// and the phone runs the CTAP2 getAssertion on the YubiKey's FIDO applet over NFC, with the PIN entered on the
// phone (user verification). The private key never leaves the YubiKey; PIN and tap stay required.
//
//	age-plugin-yubikey-phone ssh-opts [key file…]   prints the ssh arguments that route those keys here, one
//	                                                per line (default key file: $KEYTAP_SSH_KEY)
//
// stdin of sk-sign:   keytap-sk-v1 / alg <0 ecdsa|1 ed25519> / flags <n> / application <s> /
//                     key_handle <hex> / data <hex>
// stdout of sk-sign:  ok <flags> <counter> <sig_r hex> <sig_s hex or ->   |   error <sk error code> <message>

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	skAlgECDSA   = 0
	skAlgEd25519 = 1
	skFlagUP     = 0x01
	skFlagUV     = 0x04

	skErrGeneral     = -1
	skErrUnsupported = -2
)

type skRequest struct {
	alg         int
	flags       uint8
	application string
	keyHandle   []byte
	data        []byte
}

func parseSKRequest(r io.Reader) (*skRequest, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	q := &skRequest{alg: -1}
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			if line != "keytap-sk-v1" {
				return nil, fmt.Errorf("unknown provider protocol %q", line)
			}
			first = false
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		var err error
		switch k {
		case "alg":
			q.alg, err = strconv.Atoi(v)
		case "flags":
			var n int
			n, err = strconv.Atoi(v)
			q.flags = uint8(n)
		case "application":
			q.application = v
		case "key_handle":
			q.keyHandle, err = hex.DecodeString(v)
		case "data":
			q.data, err = hex.DecodeString(v)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
	}
	switch {
	case first:
		return nil, errors.New("empty request")
	case q.alg != skAlgECDSA && q.alg != skAlgEd25519:
		return nil, fmt.Errorf("unsupported algorithm %d", q.alg)
	case !strings.HasPrefix(q.application, "ssh:"):
		return nil, fmt.Errorf("application %q is not an ssh: application", q.application)
	case len(q.keyHandle) == 0 || len(q.keyHandle) > 1024:
		return nil, errors.New("missing or oversized key handle")
	}
	return q, nil
}

// sshBuf reads the SSH wire encoding (RFC 4251).
type sshBuf struct{ b []byte }

func (s *sshBuf) str() ([]byte, bool) {
	if len(s.b) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(s.b)
	if uint64(len(s.b)-4) < uint64(n) {
		return nil, false
	}
	v := s.b[4 : 4+n]
	s.b = s.b[4+n:]
	return v, true
}

func (s *sshBuf) byte1() (byte, bool) {
	if len(s.b) < 1 {
		return 0, false
	}
	v := s.b[0]
	s.b = s.b[1:]
	return v, true
}

// skPublicKey is the public half of an sk key, from the key blob ssh offers in a login.
type skPublicKey struct {
	ed25519     ed25519.PublicKey
	ecdsa       *ecdsa.PublicKey
	application string
	blob        []byte
}

func parseSKBlob(blob []byte) (*skPublicKey, bool) {
	s := &sshBuf{blob}
	typ, ok := s.str()
	if !ok {
		return nil, false
	}
	k := &skPublicKey{blob: blob}
	switch string(typ) {
	case "sk-ssh-ed25519@openssh.com":
		pk, ok := s.str()
		if !ok || len(pk) != ed25519.PublicKeySize {
			return nil, false
		}
		k.ed25519 = ed25519.PublicKey(pk)
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		curve, ok1 := s.str()
		q, ok2 := s.str()
		if !ok1 || !ok2 || string(curve) != "nistp256" {
			return nil, false
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), q) //nolint:staticcheck // SEC1 point from the key blob
		if x == nil {
			return nil, false
		}
		k.ecdsa = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	default:
		return nil, false
	}
	app, ok := s.str()
	if !ok {
		return nil, false
	}
	k.application = string(app)
	return k, true
}

// describeSSHData explains what ssh is signing: a login (SSH_MSG_USERAUTH_REQUEST, RFC 4252 §7, method
// "publickey" or OpenSSH's "publickey-hostbound-v00@openssh.com", which also carries the server's host key) with
// its user name and offered key, or something else (ssh-keygen -Y sign, an agent request). Display and
// verification only.
func describeSSHData(data []byte) (purpose, login string, key *skPublicKey, hostKey []byte) {
	s := &sshBuf{data}
	if _, ok := s.str(); !ok { // session identifier
		return "signature", "", nil, nil
	}
	if m, ok := s.byte1(); !ok || m != 50 {
		return "signature", "", nil, nil
	}
	user, ok1 := s.str()
	_, ok2 := s.str() // service
	method, ok3 := s.str()
	hostbound := string(method) == "publickey-hostbound-v00@openssh.com"
	if !ok1 || !ok2 || !ok3 || (string(method) != "publickey" && !hostbound) {
		return "signature", "", nil, nil
	}
	if b, ok := s.byte1(); !ok || b == 0 {
		return "signature", "", nil, nil
	}
	if _, ok := s.str(); !ok { // algorithm name
		return "login", string(user), nil, nil
	}
	blob, ok := s.str()
	if !ok {
		return "login", string(user), nil, nil
	}
	k, _ := parseSKBlob(blob)
	if hostbound {
		hostKey, _ = s.str()
	}
	return "login", string(user), k, hostKey
}

func fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// keyName finds the local public key file whose key is blob: "id_ed25519_sk" for ~/.ssh/id_ed25519_sk.pub.
func keyName(blob []byte) string {
	home, _ := os.UserHomeDir()
	want := base64.StdEncoding.EncodeToString(blob)
	for _, dir := range []string{filepath.Join(home, ".secure", "ssh"), filepath.Join(home, ".ssh")} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.pub"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil || len(b) > 4096 {
				continue
			}
			if fields := strings.Fields(string(b)); len(fields) >= 2 && fields[1] == want {
				return strings.TrimSuffix(filepath.Base(f), ".pub")
			}
		}
	}
	return ""
}

// verifyAssertion checks the authenticator's signature the way sshd will: over
// SHA-256(application) ‖ flags ‖ counter ‖ SHA-256(data).
func verifyAssertion(k *skPublicKey, application string, data []byte, a *SSHAnswer, sig []byte) error {
	appHash := sha256.Sum256([]byte(application))
	dataHash := sha256.Sum256(data)
	msg := make([]byte, 0, 69)
	msg = append(msg, appHash[:]...)
	msg = append(msg, a.Flags)
	msg = binary.BigEndian.AppendUint32(msg, a.Counter)
	msg = append(msg, dataHash[:]...)
	switch {
	case k.ed25519 != nil:
		if !ed25519.Verify(k.ed25519, msg, sig) {
			return errors.New("the YubiKey's signature does not verify against the offered key")
		}
	case k.ecdsa != nil:
		d := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k.ecdsa, d[:], sig) {
			return errors.New("the YubiKey's signature does not verify against the offered key")
		}
	}
	return nil
}

func runSKSign(stdin io.Reader, stdout io.Writer) error {
	fail := func(code int, err error) error {
		logf("sk-sign: %v", err)
		fmt.Fprintf(stdout, "error %d %s\n", code, strings.ReplaceAll(err.Error(), "\n", " "))
		return nil
	}
	q, err := parseSKRequest(stdin)
	if err != nil {
		return fail(skErrGeneral, err)
	}
	cfg, err := loadConfig()
	if err == nil && len(cfg.Devices) == 0 {
		err = errors.New("no phone is paired with this bridge; run `age-plugin-yubikey-phone pair`")
	}
	if err == nil && strings.HasPrefix(cfg.Listen, ":") {
		err = errors.New("no listen address stored; run `age-plugin-yubikey-phone pair --host IP` again")
	}
	if err != nil {
		return fail(skErrGeneral, err)
	}

	purpose, login, key, hostKey := describeSSHData(q.data)
	if key != nil && key.application != q.application {
		key = nil // not the key being used (cannot happen with a well-formed request); verify nothing against it
	}
	sum := sha256.Sum256(q.data)
	sign := &SSHSign{
		Application:      q.application,
		CredentialID:     base64.RawStdEncoding.EncodeToString(q.keyHandle),
		ClientDataHash:   base64.RawStdEncoding.EncodeToString(sum[:]),
		Algorithm:        map[int]string{skAlgEd25519: "ed25519", skAlgECDSA: "es256"}[q.alg],
		UserPresence:     q.flags&skFlagUP != 0,
		UserVerification: q.flags&skFlagUV != 0,
		Purpose:          purpose,
		Login:            truncateRunes(login, 64),
	}
	if key != nil {
		sign.KeyFingerprint = fingerprint(key.blob)
		sign.KeyName = keyName(key.blob)
	}
	if len(hostKey) > 0 {
		sign.HostKey = fingerprint(hostKey)
	}
	req := &Request{Version: protoVersion, Kind: "ssh", SSH: sign, Identities: []Identity{}, Files: []File{}}
	req.Command, req.Cwd = sshRequester()

	answer, err := askPhone(sayTTY, cfg, req, func(a *Answer) error {
		if a.SSH == nil {
			return errors.New("the answer carries no signature")
		}
		sig, err := b64any(a.SSH.Signature)
		if err != nil {
			return errors.New("the signature is not base64")
		}
		if sign.UserVerification && a.SSH.Flags&skFlagUV == 0 {
			return errors.New("the YubiKey did not verify the PIN, but this key requires it")
		}
		if sign.UserPresence && a.SSH.Flags&skFlagUP == 0 {
			return errors.New("the YubiKey did not confirm presence")
		}
		if key != nil {
			return verifyAssertion(key, q.application, q.data, a.SSH, sig)
		}
		return nil
	})
	if err != nil {
		return fail(skErrGeneral, err)
	}
	sig, _ := b64any(answer.SSH.Signature)
	var r, s []byte
	switch q.alg {
	case skAlgEd25519:
		if len(sig) != ed25519.SignatureSize {
			return fail(skErrGeneral, fmt.Errorf("Ed25519 signature of %d bytes", len(sig)))
		}
		r = sig
	case skAlgECDSA:
		var es struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(sig, &es); err != nil || len(rest) > 0 || es.R == nil || es.S == nil {
			return fail(skErrGeneral, errors.New("malformed ECDSA signature"))
		}
		r, s = es.R.Bytes(), es.S.Bytes()
	}
	sHex := "-"
	if s != nil {
		sHex = hex.EncodeToString(s)
	}
	logf("request %s: ssh %s signed (%s %s)", req.Code, purpose, sign.Login, sign.KeyFingerprint)
	_, err = fmt.Fprintf(stdout, "ok %d %d %s %s\n", answer.SSH.Flags, answer.SSH.Counter, hex.EncodeToString(r), sHex)
	return err
}

// sayTTY talks to the person at the terminal: ssh runs the provider in ssh-sk-helper, whose stdout is our
// protocol, so the message goes to the controlling terminal (or stderr without one).
func sayTTY(msg string) {
	if tty, err := os.OpenFile(ttyPath, os.O_WRONLY, 0); err == nil {
		fmt.Fprintln(tty, msg)
		tty.Close()
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

// skProviderPath finds keytap-sk.dylib (keytap-sk.so on Linux) next to this program or in ../lib.
func skProviderPath() string {
	if p := os.Getenv("KEYTAP_SK_PROVIDER"); p != "" {
		return p
	}
	name := "keytap-sk.so"
	if exeSuffix == "" && isDarwin {
		name = "keytap-sk.dylib"
	}
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(self); err == nil {
		self = r
	}
	dir := filepath.Dir(self)
	for _, c := range []string{filepath.Join(dir, "..", "lib", name), filepath.Join(dir, name)} {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func runSSHOpts(args []string, stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Devices) == 0 {
		return errors.New("no phone is paired with this bridge (yk pair-phone)")
	}
	provider := skProviderPath()
	if provider == "" {
		return errors.New("keytap-sk.dylib not found next to the bridge or in ../lib (install the bridge release again)")
	}
	keys := args
	if len(keys) == 0 && os.Getenv("KEYTAP_SSH_KEY") != "" {
		keys = []string{os.Getenv("KEYTAP_SSH_KEY")}
	}
	if len(keys) == 0 {
		return errors.New("no key file: pass the FIDO2 key handle file(s), or set KEYTAP_SSH_KEY")
	}
	for _, k := range keys {
		if _, err := os.Stat(k); err != nil {
			return fmt.Errorf("key file %s: %w", k, err)
		}
	}
	out := []string{"-o", "SecurityKeyProvider=" + provider, "-o", "IdentitiesOnly=yes"}
	for _, k := range keys {
		out = append(out, "-i", k)
	}
	_, err = fmt.Fprintln(stdout, strings.Join(out, "\n"))
	return err
}
