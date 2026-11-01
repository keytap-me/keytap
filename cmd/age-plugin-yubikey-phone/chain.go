package main

// A chain: everything one command (one sops run, one ssh login) asks of the phone, approved with ONE PIN and
// ONE tap, whichever of the computer's YubiKeys is tapped.
//
// sops starts the plugin once per recipient and ssh tries one identity after the other, so the request for
// the tapped key may come second, third or fourth. The first request goes to the phone; if the tapped key is
// not the one it needs, the phone answers "held" with the tapped key's serial and keeps the key's session
// open. From then on every request for another key is answered "not here" at once, without the phone, and
// the first one for the held key goes into the open session as a continuation. One unwrap (or one
// signature) ends the chain.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type outcome int

const (
	outAnswered outcome = iota
	outNotHere
	outWithdrawn
	outTimedOut
	outDeclined
	outError
)

func (o outcome) String() string {
	return [...]string{"answered", "nothere", "withdrawn", "timeout", "declined", "error"}[o]
}

// exitCode is what a command run with an explicit --session exits with (the race router reads it).
func (o outcome) exitCode() int {
	return [...]int{0, 6, 3, 4, 5, 1}[o]
}

func outcomeOf(s string) outcome {
	for o := outAnswered; o <= outError; o++ {
		if o.String() == s {
			return o
		}
	}
	return outError
}

type chainState int

const (
	stIdle    chainState = iota // nothing asked yet
	stPending                   // a request waits for the phone
	stHeld                      // the phone holds key `held`, waiting for its request
	stDone                      // one unwrap / signature delivered
	stEnded                     // withdrawn, declined, timed out or abandoned
)

type chain struct {
	cfg  *Config
	idle time.Duration // how long a held key waits for its request before the chain gives up

	run sync.Mutex // one request at a time (sops and ssh ask sequentially anyway)

	mu       sync.Mutex
	state    chainState
	held     uint32
	lastID   string
	phone    *phoneSession
	endOut   outcome
	endWhy   string
	timer    *time.Timer
	watchers chan struct{} // closed and replaced on every change (status --wait)
}

func newChain(cfg *Config, idle time.Duration) *chain {
	return &chain{cfg: cfg, idle: idle, watchers: make(chan struct{})}
}

func (c *chain) notify() {
	c.mu.Lock()
	close(c.watchers)
	c.watchers = make(chan struct{})
	c.mu.Unlock()
}

// changes returns a channel closed at the next change.
func (c *chain) changes() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.watchers
}

// status is the router's view: pending | engaged | answered | gone (answered is set by the holder for a
// result nobody has collected yet).
func (c *chain) status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case stPending:
		if c.phone != nil && c.phone.isEngaged() {
			return "engaged"
		}
		return "pending"
	case stHeld:
		return "engaged"
	case stIdle:
		return "pending"
	default:
		return "gone"
	}
}

func (c *chain) engaged() bool { return c.status() == "engaged" }

func (c *chain) finished() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == stDone || c.state == stEnded
}

// end stops the chain and tells the phone why.
func (c *chain) end(out outcome, reason string) {
	c.mu.Lock()
	if c.state == stDone || c.state == stEnded {
		c.mu.Unlock()
		return
	}
	c.state = stEnded
	c.endOut, c.endWhy = out, reason
	p, last := c.phone, c.lastID
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	if p != nil {
		p.endWith(last, reason)
	}
	logf("chain ended (%s): %s", out, reason)
	c.notify()
}

func (c *chain) finishDone() {
	c.mu.Lock()
	c.state = stDone
	p := c.phone
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	if p != nil {
		p.mu.Lock()
		pn := p.push
		p.mu.Unlock()
		if pn != nil {
			go pn.clear()
		}
		go func() { time.Sleep(time.Second); p.close() }()
	}
	c.notify()
}

// armIdle (re)starts the held key's wait: no request for it within c.idle and the chain gives up.
func (c *chain) armIdle(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(c.idle, func() {
		c.end(outNotHere, label+" is not one of the keys this request can use")
	})
}

func (c *chain) stopIdle() {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
}

// ensurePhone opens the phone session for the chain's first request.
func (c *chain) ensurePhone(ctx context.Context) (*phoneSession, error) {
	c.mu.Lock()
	p := c.phone
	c.mu.Unlock()
	if p != nil {
		return p, nil
	}
	p, err := openPhone(ctx, c.cfg)
	if err != nil {
		return nil, err
	}
	p.onChange = c.notify
	c.mu.Lock()
	c.phone = p
	ended, why := c.state == stEnded, c.endWhy
	c.mu.Unlock()
	if ended { // withdrawn while the listener was being opened
		p.end(why)
		return nil, errWithdrawn
	}
	return p, nil
}

func (c *chain) endedOutcome() outcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stDone {
		return outNotHere // the chain's one unwrap is spent
	}
	return c.endOut
}

// exchange sends one request into the chain and turns the answer into the next state. forKey is the serial
// the request needs (0 = unknown, e.g. an ssh key not in keys.conf).
func (c *chain) exchange(ctx context.Context, say func(string), req *Request, check func(*Answer) error) (*Answer, outcome, error) {
	c.mu.Lock()
	state, prev := c.state, c.lastID
	c.mu.Unlock()
	p, err := c.ensurePhone(ctx)
	if errors.Is(err, errWithdrawn) {
		return nil, c.endedOutcome(), err
	}
	if err != nil {
		c.end(outError, err.Error())
		return nil, outError, err
	}
	if state == stIdle {
		c.mu.Lock()
		if c.state == stIdle {
			c.state = stPending
		}
		c.mu.Unlock()
		c.notify()
	}
	if state != stHeld {
		prev = ""
	}
	c.stopIdle()
	a, err := p.ask(ctx, say, req, prev, check)
	c.mu.Lock()
	c.lastID = req.ID
	c.mu.Unlock()
	switch {
	case err == nil && a.Held != nil:
		c.mu.Lock()
		c.state, c.held = stHeld, a.Held.Serial
		c.mu.Unlock()
		c.armIdle(keyLabel(knownKeys(), a.Held.Serial))
		c.notify()
		return a, outNotHere, nil
	case err == nil:
		return a, outAnswered, nil
	case errors.Is(err, errDeclined):
		c.end(outDeclined, "declined on the phone")
		return nil, outDeclined, fmt.Errorf("request %s was declined on the phone", req.Code)
	case errors.Is(err, errTimedOut):
		c.end(outTimedOut, "expired")
		return nil, outTimedOut, fmt.Errorf("request %s expired without an answer from the phone", req.Code)
	default:
		return nil, c.endedOutcome(), fmt.Errorf("request %s was withdrawn", req.Code)
	}
}

// ageQuery is one plugin invocation: our stanzas of every file, the identity stubs age passed in.
type ageQuery struct {
	Files      []File     `json:"files"`
	Identities []Identity `json:"identities"`
	Note       string     `json:"note,omitempty"`
	Command    string     `json:"command,omitempty"`
	Cwd        string     `json:"cwd,omitempty"`
}

func serialOfTag(ids []Identity, tag string) uint32 {
	for _, id := range ids {
		if id.Tag == tag {
			return id.Serial
		}
	}
	return 0
}

// unwrap answers one invocation. Results carry file keys for answered files; files left out are "not here".
func (c *chain) unwrap(ctx context.Context, say func(string), q *ageQuery) ([]Result, outcome, error) {
	c.run.Lock()
	defer c.run.Unlock()
	c.mu.Lock()
	state, held := c.state, c.held
	c.mu.Unlock()
	if state == stDone || state == stEnded {
		return nil, c.endedOutcome(), nil
	}
	keys := knownKeys()
	files := q.Files
	if state == stHeld {
		files = nil
		for _, f := range q.Files {
			var mine []PivStanza
			for _, st := range f.Stanzas {
				if serialOfTag(q.Identities, st.Tag) == held {
					mine = append(mine, st)
				}
			}
			if len(mine) > 0 {
				files = append(files, File{Index: f.Index, Stanzas: mine})
			}
		}
		if len(files) == 0 {
			c.armIdle(keyLabel(keys, held)) // the next invocation may be the held key's
			return nil, outNotHere, nil
		}
	}
	if len(files) == 0 {
		return nil, outNotHere, nil
	}
	// The computer's keys (keys.conf, identity file) first, then any stub age passed that they do not list:
	// age starts the plugin once per identity, so one invocation sees one stub.
	var serials []uint32
	for _, k := range keys {
		serials = append(serials, k.Serial)
	}
	for _, id := range q.Identities {
		serials = append(serials, id.Serial)
	}
	infos := keyInfos(keys, serials)
	req := &Request{Kind: "", Files: files, Identities: q.Identities, Keys: infos, Note: q.Note, Command: q.Command, Cwd: q.Cwd}
	req.Default = pickDefault(infos, serialOfTag(q.Identities, files[0].Stanzas[0].Tag))
	if state == stHeld {
		req.Default = held
	}
	a, out, err := c.exchange(ctx, say, req, nil)
	if out != outAnswered {
		return nil, out, err
	}
	var results []Result
	for _, r := range a.Results {
		if r.FileKey != "" {
			results = append(results, r)
		}
	}
	if len(results) == 0 {
		// The phone tapped the right key but could not unwrap (corrupt stanza, wrong slot): not ours after all.
		msg := "the phone could not unwrap this file key"
		if len(a.Results) > 0 && a.Results[0].Error != "" {
			msg = a.Results[0].Error
		}
		c.end(outError, msg)
		return a.Results, outError, errors.New(msg)
	}
	setLastKey(serialOfTag(q.Identities, files[0].Stanzas[0].Tag))
	c.finishDone()
	return a.Results, outAnswered, nil
}

// sign answers one OpenSSH sk signature (a login's identity attempt).
func (c *chain) sign(ctx context.Context, say func(string), q *skRequest, command, cwd, note string) (*SSHAnswer, outcome, error) {
	c.run.Lock()
	defer c.run.Unlock()
	c.mu.Lock()
	state, held := c.state, c.held
	c.mu.Unlock()
	if state == stDone || state == stEnded {
		return nil, c.endedOutcome(), nil
	}
	keys := knownKeys()
	sign, key, check := buildSSHSign(q, keys)
	if state == stHeld && sign.KeySerial != 0 && sign.KeySerial != held {
		c.armIdle(keyLabel(keys, held))
		return nil, outNotHere, nil
	}
	var serials []uint32
	for _, k := range keys {
		if len(k.SSH) > 0 {
			serials = append(serials, k.Serial)
		}
	}
	if len(serials) == 0 {
		for _, k := range keys {
			serials = append(serials, k.Serial)
		}
	}
	if sign.KeySerial != 0 {
		serials = append([]uint32{sign.KeySerial}, serials...)
	}
	infos := keyInfos(keys, serials)
	req := &Request{Kind: "ssh", SSH: sign, Keys: infos, Note: note, Command: command, Cwd: cwd}
	req.Default = pickDefault(infos, sign.KeySerial)
	if sign.KeySerial != 0 {
		req.Default = sign.KeySerial
	}
	if state == stHeld {
		req.Default = held
	}
	a, out, err := c.exchange(ctx, say, req, check)
	if out != outAnswered {
		return nil, out, err
	}
	_ = key
	if sign.KeySerial != 0 {
		setLastKey(sign.KeySerial)
	} else if held != 0 {
		setLastKey(held)
	}
	c.finishDone()
	return a.SSH, outAnswered, nil
}
