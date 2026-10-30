package main

// age plugin identity-v1, as `age-plugin-yubikey` speaks it — except that the ECDH happens on
// a YubiKey tapped on the user's iPhone. Stanza layout verified against
// str4d/age-plugin-yubikey v0.5.1 (src/format.rs, src/key.rs):
//   -> piv-p256 <tag: 4 bytes b64> <epk: 33 bytes SEC1-compressed b64>
//   <body: 32 bytes = ChaCha20-Poly1305(wrap key, zero nonce, 16-byte file key)>
//   tag = SHA-256(compressed recipient)[0:4]; identity data = serial (u32 LE) ‖ retired slot ‖ tag

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	identityHRP  = "age-plugin-yubikey-"
	stanzaTag    = "piv-p256"
	requestTTL   = 120 * time.Second
	protoVersion = 1
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

func runIdentityPlugin(stdin io.Reader, stdout io.Writer) error {
	c := &ageConn{r: bufio.NewReader(stdin), w: stdout}

	// Phase 1: the client tells us the identities and the stanzas of every file.
	var identities []Identity
	type fileStanzas struct {
		index   int
		stanzas []PivStanza
		invalid []int
	}
	files := map[int]*fileStanzas{}
	var order []int
	stanzaCount := map[int]int{}
	for {
		s, err := readStanza(c.r)
		if err != nil {
			return fmt.Errorf("phase 1: %w", err)
		}
		if s.Tag == "done" {
			break
		}
		switch s.Tag {
		case "add-identity":
			if len(s.Args) == 1 {
				if id, ok := parseIdentity(s.Args[0]); ok {
					identities = append(identities, *id)
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
			f := files[fi]
			if f == nil {
				f = &fileStanzas{index: fi}
				files[fi] = f
				order = append(order, fi)
			}
			args := s.Args[2:]
			if len(args) != 2 || !validLen(args[0], 4) || !validLen(args[1], 33) || len(s.Body) != 32 {
				f.invalid = append(f.invalid, si)
				continue
			}
			f.stanzas = append(f.stanzas, PivStanza{
				StanzaIndex: si, Tag: args[0], EPK: args[1],
				Body: base64.RawStdEncoding.EncodeToString(s.Body),
			})
		}
	}

	// Phase 2. A structurally invalid piv-p256 stanza poisons its whole file (as upstream does);
	// only stanzas whose tag matches one of our identities AND a YubiKey registered with a paired
	// phone go to the phone. Everything else is "not here", answered at once.
	cfg, cfgErr := loadConfig()
	var registered map[string]bool
	if cfgErr == nil {
		if registered = cfg.registeredTags(); len(registered) == 0 {
			registered = nil // a pairing from before key registration: answer for any key
		}
	}
	req := &Request{Version: protoVersion}
	for _, fi := range order {
		f := files[fi]
		if len(f.invalid) > 0 {
			for _, si := range f.invalid {
				if _, err := c.send("error", []string{"stanza", strconv.Itoa(fi), strconv.Itoa(si)}, []byte("invalid piv-p256 stanza")); err != nil {
					return err
				}
			}
			continue
		}
		var mine []PivStanza
		for _, st := range f.stanzas {
			for _, id := range identities {
				if st.Tag == id.Tag && (registered == nil || registered[st.Tag]) {
					mine = append(mine, st)
					break
				}
			}
		}
		if len(mine) > 0 {
			req.Files = append(req.Files, File{Index: fi, Stanzas: mine})
		}
	}
	if len(req.Files) == 0 {
		return finish(c)
	}
	// Only the keys this request can actually be approved with (the identity file lists every
	// YubiKey; the phone shows these serials and answers with whichever one is tapped).
	used := map[string]bool{}
	for _, f := range req.Files {
		for _, st := range f.Stanzas {
			used[st.Tag] = true
		}
	}
	for _, id := range identities {
		if used[id.Tag] {
			req.Identities = append(req.Identities, id)
		}
	}

	err := cfgErr
	if err == nil && strings.HasPrefix(cfg.Listen, ":") {
		err = fmt.Errorf("no listen address stored; run `age-plugin-yubikey-phone pair --host IP` again")
	}
	if err == nil && len(cfg.Devices) == 0 {
		err = fmt.Errorf("no phone is paired with this bridge; run `age-plugin-yubikey-phone pair`")
	}
	if err != nil {
		c.send("error", []string{"internal"}, []byte("KeyTap: "+err.Error()))
		return finish(c)
	}

	answer, err := askPhone(c, cfg, req, nil)
	if err != nil {
		logf("request %s: %v", req.Code, err)
		c.send("error", []string{"internal"}, []byte("KeyTap: "+err.Error()))
		return finish(c)
	}
	got := map[int]bool{}
	for _, r := range answer.Results {
		if got[r.Index] || !hasFile(req, r.Index) {
			continue
		}
		key, kerr := b64any(r.FileKey)
		if r.FileKey == "" || kerr != nil || len(key) != 16 {
			msg := r.Error
			if msg == "" {
				msg = "the phone could not unwrap this file key"
			}
			if _, err := c.send("error", []string{"stanza", strconv.Itoa(r.Index), strconv.Itoa(firstStanza(req, r.Index))}, []byte(msg)); err != nil {
				return err
			}
			continue
		}
		got[r.Index] = true
		if _, err := c.send("file-key", []string{strconv.Itoa(r.Index)}, key); err != nil {
			return err
		}
		clear(key)
	}
	return finish(c)
}

func finish(c *ageConn) error {
	return writeStanza(c.w, "done", nil, nil)
}

func validLen(arg string, n int) bool {
	b, err := base64.RawStdEncoding.Strict().DecodeString(arg)
	return err == nil && len(b) == n
}

func hasFile(req *Request, idx int) bool {
	return firstStanza(req, idx) >= 0
}

func firstStanza(req *Request, idx int) int {
	for _, f := range req.Files {
		if f.Index == idx && len(f.Stanzas) > 0 {
			return f.Stanzas[0].StanzaIndex
		}
	}
	return -1
}

func askPhone(c *ageConn, cfg *Config, req *Request, check func(*Answer) error) (*Answer, error) {
	id := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(id)
	rand.Read(nonce)
	req.ID = base64.RawURLEncoding.EncodeToString(id)
	req.Code = displayCode(id)
	req.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	req.CreatedAt = time.Now().UTC().Truncate(time.Second)
	req.ExpiresAt = req.CreatedAt.Add(requestTTL)
	req.Host = cfg.displayName()
	req.User = os.Getenv("USER")
	req.Command, req.Cwd = requester()

	cert, _, err := loadOrCreateCert()
	if err != nil {
		return nil, fmt.Errorf("bridge certificate: %w", err)
	}
	reqBytes, _ := json.Marshal(req)

	ctx, cancel := context.WithDeadline(context.Background(), req.ExpiresAt)
	defer cancel()
	notify(c, fmt.Sprintf("KeyTap: approve request %s on your iPhone (expires %s)", req.Code, req.ExpiresAt.Local().Format("15:04:05")))
	ln, err := listen(ctx, cfg.Listen, cert)
	if err != nil {
		return nil, err
	}
	s := &server{cfg: cfg, pending: &pending{req: req, bytes: reqBytes, done: make(chan *Answer, 1), check: check}}
	srv := serve(ln, s.handler())
	defer func() {
		// Let the answer's 204 reach the phone before the listener goes away.
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		srv.Shutdown(sctx)
	}()
	logf("request %s: waiting (%d file(s), command %q)", req.Code, len(req.Files), req.Command)

	select {
	case a := <-s.pending.done:
		if a.Declined {
			return nil, fmt.Errorf("request %s was declined on the phone", req.Code)
		}
		return a, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("request %s expired without an answer from the phone", req.Code)
	}
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
