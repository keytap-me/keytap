package main

// The holder: one detached process per session (one sops run, one ssh login) that owns the chain and the
// phone listener. Every plugin invocation of the session talks to it over a unix socket instead of to the
// phone, so the chain outlives the invocation that started it.
//
//   ~/.secure/keytap/sessions/s-<id>.sock    the holder's socket (dir 0700, socket 0600)
//   ~/.secure/keytap/sessions/s-<id>.lock    its pid (one holder per session)
//
// Session id: --session, else $KEYTAP_SESSION, else the parent process (sops / age; for sk-sign the ssh
// process). The holder ends when its chain ends, when a numeric session id's process exits, on SIGTERM
// (= withdraw --force), and after at most firstRequestTTL + a minute.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var sessionRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// holderIdle: after the phone holds a key, how long the holder waits for the request that key can answer.
const holderIdle = 5 * time.Second

// routerSilence: a non-pid session with no client contact for this long is withdrawn.
const routerSilence = 45 * time.Second

type skWire struct {
	Alg         int    `json:"alg"`
	Flags       uint8  `json:"flags"`
	Application string `json:"application"`
	KeyHandle   string `json:"key_handle"`
	Data        string `json:"data"`
}

func wireSK(q *skRequest) *skWire {
	return &skWire{Alg: q.alg, Flags: q.flags, Application: q.application,
		KeyHandle: base64.RawStdEncoding.EncodeToString(q.keyHandle), Data: base64.RawStdEncoding.EncodeToString(q.data)}
}

func (w *skWire) request() (*skRequest, error) {
	kh, err1 := base64.RawStdEncoding.DecodeString(w.KeyHandle)
	data, err2 := base64.RawStdEncoding.DecodeString(w.Data)
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad sk request")
	}
	return &skRequest{alg: w.Alg, flags: w.Flags, application: w.Application, keyHandle: kh, data: data}, nil
}

type holderReq struct {
	Op     string    `json:"op"` // unwrap | hold | sign | status | withdraw
	Digest string    `json:"digest,omitempty"`
	Age    *ageQuery `json:"age,omitempty"`
	SK     *skWire   `json:"sk,omitempty"`
	Note   string    `json:"note,omitempty"`
	Cmd    string    `json:"command,omitempty"`
	Cwd    string    `json:"cwd,omitempty"`
	Force  bool      `json:"force,omitempty"`
	Reason string    `json:"reason,omitempty"`
	WaitMS int       `json:"wait_ms,omitempty"`
	Since  string    `json:"since,omitempty"`
}

type holderResp struct {
	Say     string     `json:"say,omitempty"` // a line for the terminal; more lines follow
	Final   bool       `json:"final,omitempty"`
	Status  string     `json:"status,omitempty"`
	Results []Result   `json:"results,omitempty"`
	SSH     *SSHAnswer `json:"ssh,omitempty"`
	State   string     `json:"state,omitempty"`
	Message string     `json:"message,omitempty"`
}

func sessionDir() string { return filepath.Join(stateDir(), "sessions") }
func sessionSock(id string) string {
	return filepath.Join(sessionDir(), "s-"+id+".sock")
}
func sessionLock(id string) string {
	return filepath.Join(sessionDir(), "s-"+id+".lock")
}

func validSession(id string) error {
	if !sessionRE.MatchString(id) {
		return fmt.Errorf("session id %q: use 1–64 of A-Z a-z 0-9 . _ -", id)
	}
	return nil
}

func dialHolder(id string) (net.Conn, error) {
	return net.DialTimeout("unix", sessionSock(id), time.Second)
}

// ensureHolder connects to the session's holder, starting it (detached) if there is none.
func ensureHolder(id string) (net.Conn, error) {
	if c, err := dialHolder(id); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(sessionDir(), 0o700); err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, "__holder", "--session", id)
	cmd.Env = os.Environ()
	detach(cmd)
	if null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0); err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
		defer null.Close()
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the KeyTap holder: %w", err)
	}
	go cmd.Wait() // reap it if it exits while we run (it normally outlives us)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := dialHolder(id); err == nil {
			return c, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, errors.New("the KeyTap holder did not start")
}

// holderCall sends one request and reads the reply, printing the holder's terminal lines through say.
func holderCall(id string, req *holderReq, say func(string)) (*holderResp, error) {
	var c net.Conn
	var err error
	if req.Op == "status" || req.Op == "withdraw" {
		c, err = dialHolder(id)
	} else {
		c, err = ensureHolder(id)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bufio.NewReader(c))
	for {
		var r holderResp
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("the KeyTap holder went away: %w", err)
		}
		if r.Say != "" && !r.Final {
			if say != nil {
				say(r.Say)
			}
			continue
		}
		return &r, nil
	}
}

func phase1Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ---- the holder process ----

type specResult struct {
	done    chan struct{}
	doneAt  time.Time
	results []Result
	out     outcome
	msg     string
	taken   bool
}

type holder struct {
	id      string
	chain   *chain
	mu      sync.Mutex
	spec    map[string]*specResult
	lastSay string
	active  int
	contact time.Time // the last request from any client (a router polls status)
	ctx     context.Context
	cancel  context.CancelFunc
}

func runHolder(id string) error {
	if err := validSession(id); err != nil {
		return err
	}
	if err := os.MkdirAll(sessionDir(), 0o700); err != nil {
		return err
	}
	os.Chmod(sessionDir(), 0o700)
	// One holder per session: the lock holds our pid; a stale one (dead pid) is taken over.
	for i := 0; ; i++ {
		f, err := os.OpenFile(sessionLock(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			break
		}
		b, _ := os.ReadFile(sessionLock(id))
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if processAlive(pid) || i > 3 {
			return nil // another holder serves this session
		}
		os.Remove(sessionLock(id))
	}
	defer os.Remove(sessionLock(id))
	os.Remove(sessionSock(id))
	ln, err := net.Listen("unix", sessionSock(id))
	if err != nil {
		return err
	}
	os.Chmod(sessionSock(id), 0o600)
	defer os.Remove(sessionSock(id))

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), firstRequestTTL+time.Minute)
	defer cancel()
	h := &holder{id: id, chain: newChain(cfg, holderIdle), spec: map[string]*specResult{}, ctx: ctx, cancel: cancel, contact: time.Now()}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		<-sig
		h.chain.end(outWithdrawn, "answered elsewhere")
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	// A numeric session id is the asking process (sops, ssh): when it is gone, nobody will collect anything.
	if pid, err := strconv.Atoi(id); err == nil {
		go func() {
			for ctx.Err() == nil {
				time.Sleep(500 * time.Millisecond)
				if !processAlive(pid) {
					h.chain.end(outWithdrawn, h.goneReason())
					time.Sleep(endGrace + time.Second) // let the phone read why
					cancel()
					return
				}
			}
		}()
	} else {
		// A router's session: it polls status while it races. Silence means it is gone; a request it
		// started must not keep the listener (and the phone prompt) for the full five minutes.
		go func() {
			for ctx.Err() == nil {
				time.Sleep(time.Second)
				h.mu.Lock()
				quiet := time.Since(h.contact) > routerSilence && h.active == 0
				h.mu.Unlock()
				if quiet && !h.chain.engaged() && !h.chain.finished() {
					h.chain.end(outWithdrawn, "the computer stopped waiting")
				}
			}
		}()
	}
	// Exit once the chain is over and every result was collected (or nobody came for it).
	go func() {
		for ctx.Err() == nil {
			ch := h.chain.changes()
			if h.chain.finished() {
				grace := time.NewTimer(endGrace + time.Second)
				for {
					select {
					case <-grace.C:
						if h.idle() {
							cancel()
							return
						}
						grace.Reset(500 * time.Millisecond)
						continue
					case <-ctx.Done():
						return
					}
				}
			}
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
	}()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	logf("holder %s: up", id)
	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		h.mu.Lock()
		h.active++
		h.mu.Unlock()
		go func() {
			defer func() {
				conn.Close()
				h.mu.Lock()
				h.active--
				h.mu.Unlock()
			}()
			h.serve(conn)
		}()
	}
	h.chain.end(outWithdrawn, "cancelled on the computer")
	logf("holder %s: down", id)
	return nil
}

func (h *holder) goneReason() string {
	h.chain.mu.Lock()
	held, state := h.chain.held, h.chain.state
	h.chain.mu.Unlock()
	if state == stHeld {
		return keyLabel(knownKeys(), held) + " is not one of the keys this request can use"
	}
	return "the command on the computer ended"
}

func (h *holder) idle() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active > 0 {
		return false
	}
	for _, s := range h.spec {
		select {
		case <-s.done:
			// a file key nobody collected yet: wait a little for the invocation that attaches to it
			if !s.taken && s.out == outAnswered && time.Since(s.doneAt) < 30*time.Second {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (h *holder) serve(conn net.Conn) {
	enc := json.NewEncoder(conn)
	var mu sync.Mutex
	send := func(r holderResp) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(r)
	}
	var req holderReq
	if err := json.NewDecoder(io.LimitReader(conn, 4<<20)).Decode(&req); err != nil {
		return
	}
	h.mu.Lock()
	h.contact = time.Now()
	h.mu.Unlock()
	say := func(m string) {
		h.mu.Lock()
		h.lastSay = m
		h.mu.Unlock()
		send(holderResp{Say: m})
	}
	switch req.Op {
	case "status":
		send(holderResp{Final: true, State: h.waitStatus(req.Since, req.WaitMS)})
	case "withdraw":
		if h.chain.engaged() && !req.Force {
			send(holderResp{Final: true, Status: "refused", Message: "the request is open on the phone"})
			return
		}
		reason := req.Reason
		if reason == "" {
			reason = "answered elsewhere"
		}
		h.chain.end(outWithdrawn, reason)
		send(holderResp{Final: true, Status: "ok"})
	case "hold":
		if req.Age == nil {
			send(holderResp{Final: true, Status: "error", Message: "no stanzas"})
			return
		}
		h.mu.Lock()
		if _, ok := h.spec[req.Digest]; !ok {
			s := &specResult{done: make(chan struct{})}
			h.spec[req.Digest] = s
			go func() {
				results, out, msg := h.doUnwrap(func(m string) { h.mu.Lock(); h.lastSay = m; h.mu.Unlock() }, req.Age)
				h.mu.Lock()
				s.results, s.out, s.msg, s.doneAt = results, out, msg, time.Now()
				h.mu.Unlock()
				close(s.done)
				h.chain.notify()
			}()
		}
		h.mu.Unlock()
		send(holderResp{Final: true, Status: "ok"})
	case "unwrap":
		if req.Age == nil {
			send(holderResp{Final: true, Status: "error", Message: "no stanzas"})
			return
		}
		h.mu.Lock()
		s, ok := h.spec[req.Digest]
		if ok && s.taken {
			ok = false
		}
		if ok {
			s.taken = true
		}
		last := h.lastSay
		h.mu.Unlock()
		if ok {
			if last != "" {
				send(holderResp{Say: last})
			}
			<-s.done
			send(holderResp{Final: true, Status: s.out.String(), Results: s.results, Message: s.msg})
			return
		}
		results, out, msg := h.doUnwrap(say, req.Age)
		send(holderResp{Final: true, Status: out.String(), Results: results, Message: msg})
	case "sign":
		q, err := req.SK.request()
		if req.SK == nil || err != nil {
			send(holderResp{Final: true, Status: "error", Message: "bad sk request"})
			return
		}
		a, out, err := h.chain.sign(h.ctx, say, q, req.Cmd, req.Cwd, req.Note)
		r := holderResp{Final: true, Status: out.String(), SSH: a}
		if err != nil {
			r.Message = err.Error()
		}
		send(r)
	default:
		send(holderResp{Final: true, Status: "error", Message: "unknown op"})
	}
}

func (h *holder) doUnwrap(say func(string), q *ageQuery) ([]Result, outcome, string) {
	results, out, err := h.chain.unwrap(h.ctx, say, q)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return results, out, msg
}

// routerStatus: answered when a speculative result waits to be collected, else the chain's state.
func (h *holder) routerStatus() string {
	h.mu.Lock()
	for _, s := range h.spec {
		select {
		case <-s.done:
			if !s.taken && s.out == outAnswered {
				h.mu.Unlock()
				return "answered"
			}
		default:
		}
	}
	h.mu.Unlock()
	return h.chain.status()
}

func (h *holder) waitStatus(since string, waitMS int) string {
	st := h.routerStatus()
	if waitMS <= 0 {
		return st
	}
	if since == "" {
		since = st
	}
	deadline := time.After(time.Duration(waitMS) * time.Millisecond)
	for st == since {
		ch := h.chain.changes()
		select {
		case <-ch:
		case <-deadline:
			return st
		case <-h.ctx.Done():
			return "gone"
		}
		st = h.routerStatus()
	}
	return st
}

// ---- the router-facing commands ----

var statusCodes = map[string]int{"pending": 10, "engaged": 11, "answered": 12, "gone": 13}

func runStatus(id string, waitMS int) int {
	resp, err := holderCall(id, &holderReq{Op: "status", WaitMS: waitMS}, nil)
	st := "gone"
	if err == nil && resp.State != "" {
		st = resp.State
	}
	fmt.Println(st)
	return statusCodes[st]
}

func runWithdraw(id, reason string, force bool) int {
	resp, err := holderCall(id, &holderReq{Op: "withdraw", Reason: reason, Force: force}, nil)
	if err != nil {
		return 0 // no holder: nothing to withdraw
	}
	if resp.Status == "refused" {
		fmt.Fprintln(os.Stderr, "keytap: not withdrawn: "+resp.Message)
		return 7
	}
	return 0
}
