package main

// age plugin identity-v1, as `age-plugin-yubikey` speaks it — except that the ECDH happens on
// a YubiKey tapped on the user's iPhone. Stanza layout verified against
// str4d/age-plugin-yubikey v0.5.1 (src/format.rs, src/key.rs):
//   -> piv-p256 <tag: 4 bytes b64> <epk: 33 bytes SEC1-compressed b64>
//   <body: 32 bytes = ChaCha20-Poly1305(wrap key, zero nonce, 16-byte file key)>
//   tag = SHA-256(compressed recipient)[0:4]; identity data = serial (u32 LE) ‖ retired slot ‖ tag

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const (
	identityHRP  = "age-plugin-yubikey-"
	stanzaTag    = "piv-p256"
	requestTTL   = 300 * time.Second
	protoVersion = 2
)

type ageConn struct {
	r *bufio.Reader
	w io.Writer
}

// send writes a phase-2 command and reads the client's response stanza (ok / fail / unsupported).
func (c *ageConn) send(tag string, args []string, body []byte) (*Stanza, error) {
	if err := writeStanza(c.w, tag, args, body); err != nil {
		return nil, err
	}
	return readStanza(c.r)
}

func parseIdentity(s string) (*Identity, bool) {
	hrp, data, err := bech32Decode(s)
	if err != nil || hrp != identityHRP || len(data) < 9 {
		return nil, false
	}
	if data[4] < 0x82 || data[4] > 0x95 {
		return nil, false
	}
	return &Identity{
		Serial: binary.LittleEndian.Uint32(data[0:4]),
		Slot:   data[4],
		Tag:    base64.RawStdEncoding.EncodeToString(data[5:9]),
	}, true
}

// phase1 is age's first phase as this plugin reads it: the identities, our stanzas per file, and the
// files whose piv-p256 stanzas are malformed (they poison the file, as upstream does).
type phase1 struct {
	identities []Identity
	files      []File
	invalid    map[int][]int
	raw        []byte
}

// readPhase1 reads up to and including "-> done". raw keeps the exact bytes (the race router replays them).
// The returned reader continues after phase 1 (it may hold bytes read ahead).
func readPhase1(r io.Reader) (*phase1, *bufio.Reader, error) {
	var raw bytes.Buffer
	tee := bufio.NewReader(io.TeeReader(r, &raw))
	p := &phase1{invalid: map[int][]int{}}
	type fileStanzas struct {
		index   int
		stanzas []PivStanza
	}
	files := map[int]*fileStanzas{}
	var order []int
	stanzaCount := map[int]int{}
	for {
		s, err := readStanza(tee)
		if err != nil {
			return nil, nil, fmt.Errorf("phase 1: %w", err)
		}
		if s.Tag == "done" {
			break
		}
		switch s.Tag {
		case "add-identity":
			if len(s.Args) == 1 {
				if id, ok := parseIdentity(s.Args[0]); ok {
					p.identities = append(p.identities, *id)
				}
			}
		case "recipient-stanza":
			if len(s.Args) < 2 {
				continue
			}
			fi, err := strconv.Atoi(s.Args[0])
			if err != nil {
				continue
			}
			si := stanzaCount[fi]
			stanzaCount[fi]++
			if s.Args[1] != stanzaTag {
				continue
			}
			args := s.Args[2:]
			if len(args) != 2 || !validLen(args[0], 4) || !validLen(args[1], 33) || len(s.Body) != 32 {
				p.invalid[fi] = append(p.invalid[fi], si)
				continue
			}
			f := files[fi]
			if f == nil {
				f = &fileStanzas{index: fi}
				files[fi] = f
				order = append(order, fi)
			}
			f.stanzas = append(f.stanzas, PivStanza{
				StanzaIndex: si, Tag: args[0], EPK: args[1],
				Body: base64.RawStdEncoding.EncodeToString(s.Body),
			})
		}
	}
	// Our stanzas: tag matches an identity stub age passed in. Which YubiKeys exist is the computer's
	// business (its identity file); the phone registers none.
	for _, fi := range order {
		if len(p.invalid[fi]) > 0 {
			continue
		}
		var mine []PivStanza
		for _, st := range files[fi].stanzas {
			if serialOfTag(p.identities, st.Tag) != 0 {
				mine = append(mine, st)
			}
		}
		if len(mine) > 0 {
			p.files = append(p.files, File{Index: fi, Stanzas: mine})
		}
	}
	// readStanza reads whole lines, so the tee holds exactly phase 1 plus nothing after "done"'s body line.
	p.raw = append([]byte(nil), raw.Bytes()[:raw.Len()-tee.Buffered()]...)
	return p, tee, nil
}

// runIdentityPlugin is one age plugin invocation. It hands the stanzas to the session's holder (started
// if needed), which owns the chain to the phone, and writes what comes back. With an explicit --session the
// exit code says how it went (0 answered, 3 withdrawn, 4 timed out, 5 declined, 6 not here); without one it
// is 0, as age expects from a plugin that completed the protocol.
func runIdentityPlugin(stdin io.Reader, stdout io.Writer, session string, explicit bool) (int, error) {
	p1, in, err := readPhase1(stdin)
	if err != nil {
		return 1, err
	}
	c := &ageConn{r: in, w: stdout}
	code := func(o outcome) int {
		if explicit {
			return o.exitCode()
		}
		return 0
	}
	for fi, sis := range p1.invalid {
		for _, si := range sis {
			if _, err := c.send("error", []string{"stanza", strconv.Itoa(fi), strconv.Itoa(si)}, []byte("invalid piv-p256 stanza")); err != nil {
				return 1, err
			}
		}
	}
	if len(p1.files) == 0 {
		return code(outNotHere), finish(c)
	}
	command, cwd := requester()
	q := &ageQuery{Files: p1.files, Identities: p1.identities, Note: cleanNote(os.Getenv("KEYTAP_NOTE")), Command: command, Cwd: cwd}

	// SIGTERM / SIGINT from whoever started us (the race router) withdraws the session's phone request.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		holderCall(session, &holderReq{Op: "withdraw", Force: true, Reason: "answered elsewhere"}, nil)
		os.Exit(outWithdrawn.exitCode())
	}()

	resp, err := holderCall(session, &holderReq{Op: "unwrap", Digest: phase1Digest(p1.raw), Age: q}, func(m string) { notify(c, m) })
	if err != nil {
		c.send("error", []string{"internal"}, []byte("KeyTap: "+err.Error()))
		return 1, finish(c)
	}
	out := outcomeOf(resp.Status)
	switch out {
	case outAnswered:
		got := map[int]bool{}
		for _, r := range resp.Results {
			if got[r.Index] || !hasFile(p1.files, r.Index) || r.FileKey == "" {
				continue
			}
			key, kerr := b64any(r.FileKey)
			if kerr != nil || len(key) != 16 {
				continue
			}
			got[r.Index] = true
			if _, err := c.send("file-key", []string{strconv.Itoa(r.Index)}, key); err != nil {
				return 1, err
			}
			clear(key)
		}
	case outNotHere, outWithdrawn, outTimedOut:
		// not here: age moves on to the next identity / recipient, as with an absent YubiKey
	case outDeclined:
		for _, f := range p1.files {
			c.send("error", []string{"stanza", strconv.Itoa(f.Index), strconv.Itoa(f.Stanzas[0].StanzaIndex)}, []byte("KeyTap: "+resp.Message))
		}
	default:
		msg := resp.Message
		if msg == "" {
			msg = "the phone could not unwrap this file key"
		}
		c.send("error", []string{"internal"}, []byte("KeyTap: "+msg))
	}
	return code(out), finish(c)
}

func finish(c *ageConn) error {
	return writeStanza(c.w, "done", nil, nil)
}

func validLen(arg string, n int) bool {
	b, err := base64.RawStdEncoding.Strict().DecodeString(arg)
	return err == nil && len(b) == n
}

func hasFile(files []File, idx int) bool {
	for _, f := range files {
		if f.Index == idx && len(f.Stanzas) > 0 {
			return true
		}
	}
	return false
}

// notify tells the user what to do. sops swallows a plugin's stderr and may not render
// `msg`, so the terminal gets it directly when there is one (the relay shim does the same).
func notify(c *ageConn, msg string) {
	if c == nil {
		fmt.Println(msg)
		return
	}
	if tty, err := os.OpenFile(ttyPath, os.O_WRONLY, 0); err == nil {
		fmt.Fprintln(tty, msg)
		tty.Close()
		return
	}
	c.send("msg", nil, []byte(msg))
}

func clip(command string) string {
	if len(command) > 400 {
		return command[:400] + "…"
	}
	return command
}
