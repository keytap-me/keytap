package main

// `age-plugin-yubikey-phone agent -a SOCK [--keys DIR] [--upstream SOCK]... [--label-from keys.conf]`
//
// An ssh-agent for FIDO2 (sk) keys whose signatures come from the phone — and, raced against it, from
// upstream agents (other computers' agents forwarded here) that currently list the same key, i.e. have
// that YubiKey plugged in. The first valid signature wins; the loser is cancelled. Once the request is open
// on the phone, the phone wins (an upstream answer that arrives later is dropped).
//
// One ssh connection to the agent is one chain: ssh tries one identity after the other, and with the phone
// holding the tapped YubiKey every identity of another key fails at once, the right one signs in the same tap.
//
// Identities: the .pub files named in keys.conf (`ssh <path>`) and the sk-*.pub files in --keys DIR. The key
// handle is read from the matching private key file (the path without .pub, an unencrypted OpenSSH sk key
// file: it holds the credential id, which is useless without the YubiKey). Adding or removing identities over
// the agent protocol is refused.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	agentFailure          = 5
	agentRequestIDs       = 11
	agentIdentitiesAnswer = 12
	agentSignRequest      = 13
	agentSignResponse     = 14
	agentChainIdle        = 10 * time.Second
	upstreamRefresh       = 5 * time.Second
	upstreamStale         = 30 * time.Second
	upstreamDial          = 2 * time.Second
)

type agentKey struct {
	blob   []byte
	pub    *skPublicKey
	alg    int
	flags  uint8
	handle []byte
	serial uint32
	label  string
	path   string
}

type upstream struct {
	path    string
	mu      sync.Mutex
	blobs   map[string]bool
	fetched time.Time
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	sock := fs.String("a", "", "socket to serve the agent on (required)")
	dir := fs.String("keys", "", "directory with sk-*.pub key files (optional)")
	labels := fs.String("label-from", "", "keys.conf to read labels and ssh keys from (default $KEYTAP_KEYS or ~/.secure/keytap/keys.conf)")
	var ups stringList
	fs.Var(&ups, "upstream", "an upstream agent socket to race (repeatable)")
	fs.Parse(args)
	if *sock == "" {
		return errors.New("agent: pass -a SOCK")
	}
	if *labels != "" {
		os.Setenv("KEYTAP_KEYS", *labels)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	keys := loadAgentKeys(*dir)
	if len(keys) == 0 {
		return errors.New("agent: no FIDO2 keys found (keys.conf `ssh` entries or --keys DIR)")
	}
	var upstreams []*upstream
	for _, u := range ups {
		upstreams = append(upstreams, &upstream{path: expandHome(u), blobs: map[string]bool{}})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, u := range upstreams {
		go u.refreshLoop(ctx)
	}

	os.MkdirAll(filepath.Dir(*sock), 0o700)
	os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		return err
	}
	os.Chmod(*sock, 0o600)
	defer os.Remove(*sock)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() { <-sig; cancel(); ln.Close() }()
	logf("agent: serving %d key(s) on %s, %d upstream(s)", len(keys), *sock, len(upstreams))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go serveAgentConn(ctx, cfg, conn, keys, upstreams)
	}
}

// loadAgentKeys reads the identities: keys.conf ssh entries first (they carry the YubiKey's serial), then
// the --keys directory. A .pub whose private file is missing, encrypted or does not match is skipped (logged).
func loadAgentKeys(dir string) []*agentKey {
	known := knownKeys()
	var paths []string
	serialOf := map[string]uint32{}
	for _, k := range known {
		for _, p := range k.SSH {
			paths = append(paths, p)
			serialOf[p] = k.Serial
		}
	}
	if dir != "" {
		files, _ := filepath.Glob(filepath.Join(expandHome(dir), "*.pub"))
		paths = append(paths, files...)
	}
	var out []*agentKey
	seen := map[string]bool{}
	for _, p := range paths {
		k, err := readAgentKey(p)
		if err != nil {
			logf("agent: skipping %s: %v", p, err)
			continue
		}
		id := string(k.blob)
		if seen[id] {
			continue
		}
		seen[id] = true
		k.serial = serialOf[p]
		if k.serial == 0 {
			k.serial = sshKeySerial(known, k.blob)
		}
		if k.serial != 0 {
			k.label = keyLabel(known, k.serial)
		}
		out = append(out, k)
	}
	return out
}

func readAgentKey(pubPath string) (*agentKey, error) {
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return nil, errors.New("not an OpenSSH public key")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return nil, err
	}
	pub, ok := parseSKBlob(blob)
	if !ok {
		return nil, errors.New("not an sk-ssh-ed25519 / sk-ecdsa-sha2-nistp256 key")
	}
	priv, err := os.ReadFile(strings.TrimSuffix(pubPath, ".pub"))
	if err != nil {
		return nil, fmt.Errorf("key handle file: %w", err)
	}
	sk, err := parseSKPrivateFile(priv)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sk.blob, blob) {
		return nil, errors.New("the key handle file does not belong to this public key")
	}
	return &agentKey{blob: blob, pub: pub, alg: sk.alg, flags: sk.flags, handle: sk.handle, path: pubPath}, nil
}

type skPrivate struct {
	blob   []byte
	alg    int
	flags  uint8
	handle []byte
}

// parseSKPrivateFile reads an unencrypted openssh-key-v1 file holding one sk key (PROTOCOL.key,
// PROTOCOL.u2f): the public blob, flags and key handle. Passphrase-protected files are refused.
func parseSKPrivateFile(pemBytes []byte) (*skPrivate, error) {
	s := string(pemBytes)
	const begin, end = "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		return nil, errors.New("not an OpenSSH private key file")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s[i+len(begin):j]), ""))
	if err != nil {
		return nil, err
	}
	magic := []byte("openssh-key-v1\x00")
	if !bytes.HasPrefix(raw, magic) {
		return nil, errors.New("not an openssh-key-v1 file")
	}
	b := &sshBuf{raw[len(magic):]}
	cipher, _ := b.str()
	b.str() // kdf name
	b.str() // kdf options
	if string(cipher) != "none" {
		return nil, errors.New("the key handle file is passphrase-protected; KeyTap needs it unencrypted (it holds only the credential id)")
	}
	if len(b.b) < 4 || binary.BigEndian.Uint32(b.b) != 1 {
		return nil, errors.New("expected exactly one key")
	}
	b.b = b.b[4:]
	pubBlob, ok := b.str()
	if !ok {
		return nil, errors.New("truncated key file")
	}
	privSec, ok := b.str()
	if !ok || len(privSec) < 8 {
		return nil, errors.New("truncated key file")
	}
	p := &sshBuf{privSec[8:]} // check ints
	typ, _ := p.str()
	out := &skPrivate{blob: pubBlob}
	switch string(typ) {
	case "sk-ssh-ed25519@openssh.com":
		out.alg = skAlgEd25519
		p.str() // public key
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		out.alg = skAlgECDSA
		p.str() // curve
		p.str() // Q
	default:
		return nil, fmt.Errorf("key type %q is not an sk key", typ)
	}
	if _, ok := p.str(); !ok { // application
		return nil, errors.New("truncated sk key")
	}
	fl, ok1 := p.byte1()
	kh, ok2 := p.str()
	if !ok1 || !ok2 || len(kh) == 0 {
		return nil, errors.New("truncated sk key")
	}
	out.flags, out.handle = fl, append([]byte(nil), kh...)
	return out, nil
}

// ---- upstream agents ----

func agentRoundTrip(conn net.Conn, msg []byte) ([]byte, error) {
	if _, err := conn.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(msg))), msg...)); err != nil {
		return nil, err
	}
	var n [4]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > 1<<20 {
		return nil, errors.New("bad agent reply")
	}
	reply := make([]byte, size)
	_, err := io.ReadFull(conn, reply)
	return reply, err
}

func (u *upstream) refreshLoop(ctx context.Context) {
	for ctx.Err() == nil {
		u.refresh()
		select {
		case <-ctx.Done():
		case <-time.After(upstreamRefresh):
		}
	}
}

func (u *upstream) refresh() {
	conn, err := net.DialTimeout("unix", u.path, upstreamDial)
	if err != nil {
		u.mu.Lock()
		u.blobs = map[string]bool{}
		u.mu.Unlock()
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(upstreamDial))
	reply, err := agentRoundTrip(conn, []byte{agentRequestIDs})
	if err != nil || len(reply) < 5 || reply[0] != agentIdentitiesAnswer {
		u.mu.Lock()
		u.blobs = map[string]bool{}
		u.mu.Unlock()
		return
	}
	blobs := map[string]bool{}
	b := &sshBuf{reply[5:]}
	for i := 0; i < int(binary.BigEndian.Uint32(reply[1:5])) && i < 1000; i++ {
		blob, ok := b.str()
		if _, ok2 := b.str(); !ok || !ok2 {
			break
		}
		blobs[string(blob)] = true
	}
	u.mu.Lock()
	u.blobs, u.fetched = blobs, time.Now()
	u.mu.Unlock()
}

// lists: the upstream listed this key in a fresh enough refresh (the YubiKey is plugged in there).
func (u *upstream) lists(blob []byte) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return time.Since(u.fetched) < upstreamStale && u.blobs[string(blob)]
}

// sign forwards one sign request; the reply's signature is returned as the agent sent it.
func (u *upstream) sign(ctx context.Context, req []byte) ([]byte, error) {
	conn, err := net.DialTimeout("unix", u.path, upstreamDial)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }() // cancel = close (the other side's touch prompt runs out by itself)
	conn.SetDeadline(time.Now().Add(chainRequestTTL))
	reply, err := agentRoundTrip(conn, req)
	if err != nil {
		return nil, err
	}
	if len(reply) < 1 || reply[0] != agentSignResponse {
		return nil, errors.New("upstream refused")
	}
	sig, ok := (&sshBuf{reply[1:]}).str()
	if !ok {
		return nil, errors.New("bad upstream reply")
	}
	return sig, nil
}

// ---- signatures ----

// skSignatureBlob is the agent-protocol signature of an sk key (PROTOCOL.u2f).
func skSignatureBlob(k *agentKey, a *SSHAnswer) ([]byte, error) {
	sig, err := b64any(a.Signature)
	if err != nil {
		return nil, err
	}
	var inner []byte
	typ := "sk-ssh-ed25519@openssh.com"
	switch k.alg {
	case skAlgEd25519:
		if len(sig) != ed25519.SignatureSize {
			return nil, errors.New("bad Ed25519 signature")
		}
		inner = sig
	case skAlgECDSA:
		typ = "sk-ecdsa-sha2-nistp256@openssh.com"
		var es struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(sig, &es); err != nil || len(rest) > 0 {
			return nil, errors.New("bad ECDSA signature")
		}
		inner = append(sshStrBytes(mpint(es.R)), sshStrBytes(mpint(es.S))...)
	}
	out := append(sshStrBytes([]byte(typ)), sshStrBytes(inner)...)
	out = append(out, a.Flags)
	return binary.BigEndian.AppendUint32(out, a.Counter), nil
}

func sshStrBytes(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func mpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// verifyAgentSignature checks an upstream's signature blob exactly as sshd would.
func verifyAgentSignature(k *agentKey, data, blob []byte) error {
	b := &sshBuf{blob}
	typ, ok1 := b.str()
	inner, ok2 := b.str()
	flags, ok3 := b.byte1()
	if !ok1 || !ok2 || !ok3 || len(b.b) != 4 {
		return errors.New("malformed sk signature")
	}
	a := &SSHAnswer{Flags: flags, Counter: binary.BigEndian.Uint32(b.b)}
	var sig []byte
	switch string(typ) {
	case "sk-ssh-ed25519@openssh.com":
		sig = inner
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		ib := &sshBuf{inner}
		r, ok1 := ib.str()
		s, ok2 := ib.str()
		if !ok1 || !ok2 {
			return errors.New("malformed ECDSA signature")
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
		if err != nil {
			return err
		}
		sig = der
	default:
		return errors.New("not an sk signature")
	}
	if k.flags&skFlagUV != 0 && flags&skFlagUV == 0 {
		return errors.New("the key requires user verification")
	}
	return verifyAssertion(k.pub, k.pub.application, data, a, sig)
}

// ---- one ssh connection ----

func serveAgentConn(ctx context.Context, cfg *Config, conn net.Conn, keys []*agentKey, ups []*upstream) {
	defer conn.Close()
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := newChain(cfg, agentChainIdle)
	defer ch.end(outWithdrawn, "the ssh command ended")
	command, cwd := agentPeer(conn)
	for {
		var n [4]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(n[:])
		if size == 0 || size > 256*1024 {
			return
		}
		msg := make([]byte, size)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		var reply []byte
		switch msg[0] {
		case agentRequestIDs:
			reply = identitiesAnswer(keys, ups)
		case agentSignRequest:
			reply = agentSign(cctx, ch, msg, keys, ups, command, cwd)
		default:
			reply = []byte{agentFailure}
		}
		if _, err := conn.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(reply))), reply...)); err != nil {
			return
		}
	}
}

// identitiesAnswer orders the keys the way ssh should try them: a key plugged in at an upstream first, then
// the last key used here, then the rest (keys.conf order).
func identitiesAnswer(keys []*agentKey, ups []*upstream) []byte {
	last := lastKey()
	rank := func(k *agentKey) int {
		for _, u := range ups {
			if u.lists(k.blob) {
				return 0
			}
		}
		if last != 0 && k.serial == last {
			return 1
		}
		return 2
	}
	var ordered []*agentKey
	for r := 0; r <= 2; r++ {
		for _, k := range keys {
			if rank(k) == r {
				ordered = append(ordered, k)
			}
		}
	}
	out := []byte{agentIdentitiesAnswer}
	out = binary.BigEndian.AppendUint32(out, uint32(len(ordered)))
	for _, k := range ordered {
		comment := strings.TrimSuffix(filepath.Base(k.path), ".pub")
		if k.label != "" {
			comment += " (" + k.label + ")"
		}
		out = append(out, sshStrBytes(k.blob)...)
		out = append(out, sshStrBytes([]byte(comment))...)
	}
	return out
}

type raceResult struct {
	sig      []byte
	err      error
	out      outcome
	upstream string
}

func agentSign(ctx context.Context, ch *chain, msg []byte, keys []*agentKey, ups []*upstream, command, cwd string) []byte {
	b := &sshBuf{msg[1:]}
	blob, ok1 := b.str()
	data, ok2 := b.str()
	if !ok1 || !ok2 {
		return []byte{agentFailure}
	}
	var k *agentKey
	for _, c := range keys {
		if bytes.Equal(c.blob, blob) {
			k = c
		}
	}
	if k == nil {
		return []byte{agentFailure}
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan raceResult, len(ups)+1)
	racing := 0
	for _, u := range ups {
		if !u.lists(k.blob) {
			continue
		}
		racing++
		go func(u *upstream) {
			sig, err := u.sign(rctx, msg)
			if err == nil {
				err = verifyAgentSignature(k, data, sig)
			}
			results <- raceResult{sig: sig, err: err, upstream: u.path}
		}(u)
	}
	racing++
	go func() {
		q := &skRequest{alg: k.alg, flags: k.flags, application: k.pub.application, keyHandle: k.handle, data: data}
		a, out, err := ch.sign(rctx, nil, q, command, cwd, "")
		if out != outAnswered {
			results <- raceResult{out: out, err: err}
			return
		}
		sig, err := skSignatureBlob(k, a)
		results <- raceResult{sig: sig, err: err, out: out}
	}()
	phoneDone := false
	var fallback []byte // an upstream signature that arrived while the phone had the request open
	for racing > 0 {
		r := <-results
		racing--
		if r.upstream == "" { // the phone
			phoneDone = true
			switch {
			case r.out == outAnswered && r.err == nil:
				logf("agent: %s signed on the phone", fingerprint(k.blob))
				return append([]byte{agentSignResponse}, sshStrBytes(r.sig)...)
			case fallback != nil:
				logf("agent: %s signed by an upstream (the phone did not sign)", fingerprint(k.blob))
				return append([]byte{agentSignResponse}, sshStrBytes(fallback)...)
			case r.out == outNotHere, r.out == outDeclined:
				// the phone holds another key (or the user declined): fail now so ssh moves on
				return []byte{agentFailure}
			}
			continue // withdrawn / timed out: an upstream may still answer
		}
		if r.err != nil {
			logf("agent: upstream %s: %v", r.upstream, r.err)
			continue
		}
		if !phoneDone && ch.engaged() {
			logf("agent: upstream %s answered, but the request is open on the phone; waiting for the phone", r.upstream)
			fallback = r.sig
			continue
		}
		ch.end(outWithdrawn, "answered elsewhere")
		logf("agent: %s signed by upstream %s", fingerprint(k.blob), r.upstream)
		return append([]byte{agentSignResponse}, sshStrBytes(r.sig)...)
	}
	if fallback != nil {
		return append([]byte{agentSignResponse}, sshStrBytes(fallback)...)
	}
	return []byte{agentFailure}
}
