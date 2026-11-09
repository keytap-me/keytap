package main

// A phone session: the listener the phone polls, serving one request after another of the same chain
// (the first one, then continuations while the phone holds the tapped YubiKey), until it ends —
// answered, withdrawn ("answered elsewhere"), timed out, or the command that asked went away. After the
// end the listener answers 410 with the reason for a few seconds, so the phone can close its prompt and
// say why, then goes away.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	firstRequestTTL = 300 * time.Second
	chainRequestTTL = 60 * time.Second
	endGrace        = 4 * time.Second
)

var (
	errWithdrawn = errors.New("withdrawn")
	errTimedOut  = errors.New("timed out")
	errDeclined  = errors.New("declined on the phone")
)

type phoneSession struct {
	cfg *Config

	mu        sync.Mutex
	cur       *pending
	engaged   bool // the phone fetched a request of this session (the user has it open)
	endID     string
	endReason string
	ended     chan struct{}
	endOnce   sync.Once
	push      *pushNotifier
	srv       *http.Server
	ln        net.Listener
	onChange  func()
}

// openPhone binds the listener. It waits (up to ctx) while another request of this computer holds it.
func openPhone(ctx context.Context, cfg *Config) (*phoneSession, error) {
	switch {
	case strings.HasPrefix(cfg.Listen, ":"):
		return nil, errors.New("no listen address stored; run `age-plugin-yubikey-phone pair --host IP` again")
	case len(cfg.Devices) == 0:
		return nil, errors.New("no phone is paired with this bridge; run `age-plugin-yubikey-phone pair`")
	}
	cert, _, err := loadOrCreateCert()
	if err != nil {
		return nil, fmt.Errorf("bridge certificate: %w", err)
	}
	ln, err := listen(ctx, cfg.Listen, cert)
	if err != nil {
		return nil, err
	}
	p := &phoneSession{cfg: cfg, ln: ln, ended: make(chan struct{})}
	s := &server{cfg: cfg, session: p}
	p.srv = serve(ln, s.handler())
	return p, nil
}

func (p *phoneSession) changed() {
	if p.onChange != nil {
		p.onChange()
	}
}

func (p *phoneSession) isEngaged() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.engaged
}

// current is what GET /v1/pending serves: the open request, or the reason the session ended.
func (p *phoneSession) current() (cur *pending, endID, endReason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur, p.endID, p.endReason
}

// notifier is the push notifier of the session's first request: nil until a phone was notified.
func (p *phoneSession) notifier() *pushNotifier {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.push
}

func (p *phoneSession) fetched(id string) {
	p.mu.Lock()
	first := !p.engaged && p.cur != nil && p.cur.req.ID == id
	if first {
		p.engaged = true
	}
	p.mu.Unlock()
	if first {
		logf("request %s: opened on the phone", id[:min(6, len(id))])
		p.changed()
	}
}

// ask serves req until the phone answers it, ctx ends, or the session ends. The first request of a session
// notifies opted-in phones; continuations do not (the phone is already holding the key).
func (p *phoneSession) ask(ctx context.Context, say func(string), req *Request, prev string, check func(*Answer) error) (*Answer, error) {
	id := make([]byte, 16)
	nonce := make([]byte, 16)
	rand.Read(id)
	rand.Read(nonce)
	req.Version = protoVersion
	req.ID = base64.RawURLEncoding.EncodeToString(id)
	req.Code = displayCode(id)
	req.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	req.CreatedAt = time.Now().UTC().Truncate(time.Second)
	ttl := firstRequestTTL
	if prev != "" {
		req.Continues = prev
		ttl = chainRequestTTL
	}
	req.ExpiresAt = req.CreatedAt.Add(ttl)
	req.Host = p.cfg.displayName()
	req.User = os.Getenv("USER")
	if req.Command == "" {
		req.Command, req.Cwd = requester()
	}
	if req.Identities == nil {
		req.Identities = []Identity{}
	}
	if req.Files == nil {
		req.Files = []File{}
	}
	reqBytes, _ := json.Marshal(req)
	pd := &pending{req: req, bytes: reqBytes, done: make(chan *Answer, 1), check: check}

	select {
	case <-p.ended:
		return nil, errWithdrawn
	default:
	}
	p.mu.Lock()
	p.cur = pd
	first := p.push == nil
	p.mu.Unlock()
	p.changed()
	if first {
		if say != nil {
			say(fmt.Sprintf("KeyTap: approve request %s on your iPhone (expires %s)", req.Code, req.ExpiresAt.Local().Format("15:04:05")))
		}
		logf("request %s: waiting (kind %q, %d file(s), command %q)", req.Code, req.Kind, len(req.Files), req.Command)
		pn := notifyPhones(p.cfg, req)
		p.mu.Lock()
		p.push = pn
		p.mu.Unlock()
	} else {
		logf("request %s: continues %s in the same tap (kind %q)", req.Code, prev[:min(6, len(prev))], req.Kind)
	}

	dctx, cancel := context.WithDeadline(ctx, req.ExpiresAt)
	defer cancel()
	defer func() {
		p.mu.Lock()
		if p.cur == pd {
			p.cur = nil
		}
		p.mu.Unlock()
	}()
	select {
	case a := <-pd.done:
		if a.Declined {
			return nil, errDeclined
		}
		return a, nil
	case <-p.ended:
		return nil, errWithdrawn
	case <-dctx.Done():
		if ctx.Err() != nil {
			return nil, errWithdrawn
		}
		return nil, errTimedOut
	}
}

// end closes the session: the phone is told why (410 for a few seconds), the notification is cleared,
// then the listener goes away. Safe to call more than once; the first reason wins.
func (p *phoneSession) end(reason string) {
	p.endOnce.Do(func() {
		p.mu.Lock()
		if p.cur != nil {
			p.endID = p.cur.req.ID
		}
		p.cur = nil
		p.endReason = reason
		pn := p.push
		p.mu.Unlock()
		close(p.ended)
		p.changed()
		if pn != nil {
			go pn.clear()
		}
		go func() {
			time.Sleep(endGrace)
			p.close()
		}()
	})
}

// endWith records the id the reason is about even when no request is open any more (the last one of the
// chain was answered "held" and the phone waits for a continuation).
func (p *phoneSession) endWith(lastID, reason string) {
	p.mu.Lock()
	if p.cur == nil && p.endID == "" {
		p.endID = lastID
	}
	p.mu.Unlock()
	p.end(reason)
}

func (p *phoneSession) close() {
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.srv.Shutdown(sctx)
}

// askPhone is one request in its own session (the dry run, a pairing-free check).
func askPhone(say func(string), cfg *Config, req *Request, check func(*Answer) error) (*Answer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), firstRequestTTL)
	defer cancel()
	p, err := openPhone(ctx, cfg)
	if err != nil {
		return nil, err
	}
	a, err := p.ask(ctx, say, req, "", check)
	switch {
	case err == nil:
		p.mu.Lock()
		pn := p.push
		p.mu.Unlock()
		if pn != nil {
			pn.clear()
		}
		time.Sleep(300 * time.Millisecond) // let the 204 reach the phone
		p.close()
		return a, nil
	case errors.Is(err, errDeclined):
		p.end("declined")
		return nil, fmt.Errorf("request %s was declined on the phone", req.Code)
	case errors.Is(err, errTimedOut):
		p.end("expired")
		return nil, fmt.Errorf("request %s expired without an answer from the phone", req.Code)
	default:
		p.end("cancelled on the computer")
		return nil, err
	}
}
