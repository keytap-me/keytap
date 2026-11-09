package main

// The HTTPS endpoint the phone polls. It only exists while a decrypt is waiting for approval
// (or while `pair` runs): the phone CONNECTS OUT to it, and a refused connection simply means
// "nothing to approve". The bridge never connects to the phone.
//
//   GET  /v1/pending   Bearer → 200 the request JSON | 204 nothing pending | 410 {"id","reason"} the session ended
//   POST /v1/answer    Bearer + Secure-Enclave signature over the displayed request bytes
//   POST /v1/pair      one-time pairing code → registers the device key, returns its token (pair mode only)

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type pending struct {
	req   *Request
	bytes []byte // served verbatim; the phone signs over their hash
	done  chan *Answer
	once  sync.Once
	check func(*Answer) error // dry run: verifies the proof before the answer is accepted
}

type server struct {
	cfg     *Config
	session *phoneSession                                // nil in pair mode
	pair    func(w http.ResponseWriter, r *http.Request) // nil outside pair mode
}

func (s *server) current() (*pending, string, string) {
	if s.session == nil {
		return nil, "", ""
	}
	return s.session.current()
}

func b64any(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func (s *server) device(r *http.Request) *Device {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(tok))
	for i := range s.cfg.Devices {
		if subtle.ConstantTimeCompare(s.cfg.Devices[i].TokenSHA256, sum[:]) == 1 {
			return &s.cfg.Devices[i]
		}
	}
	return nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/pending", func(w http.ResponseWriter, r *http.Request) {
		if s.device(r) == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p, endID, reason := s.current()
		w.Header().Set("Cache-Control", "no-store")
		if p == nil && reason != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			json.NewEncoder(w).Encode(map[string]string{"id": endID, "reason": reason})
			return
		}
		if p == nil || time.Now().After(p.req.ExpiresAt) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.session.fetched(p.req.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Write(p.bytes)
	})
	mux.HandleFunc("POST /v1/answer", func(w http.ResponseWriter, r *http.Request) {
		dev := s.device(r)
		if dev == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var a Answer
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&a); err != nil {
			http.Error(w, "bad answer", http.StatusBadRequest)
			return
		}
		p, _, _ := s.current()
		switch {
		case p == nil || p.req.ID != a.ID:
			http.Error(w, "no such request", http.StatusNotFound)
			return
		case time.Now().After(p.req.ExpiresAt):
			http.Error(w, "request expired", http.StatusGone)
			return
		}
		if err := verifyAnswer(dev, p.bytes, p.req.Nonce, &a); err != nil {
			logf("request %s: rejected answer from %q: %v", p.req.Code, dev.Name, err)
			http.Error(w, "signature rejected", http.StatusForbidden)
			return
		}
		if a.Held != nil && (a.Declined || len(a.Results) > 0 || a.SSH != nil || a.Proof != "") {
			http.Error(w, "a held answer carries nothing else", http.StatusBadRequest)
			return
		}
		if p.check != nil && !a.Declined && a.Held == nil {
			if err := p.check(&a); err != nil {
				logf("request %s: dry-run proof rejected: %v", p.req.Code, err)
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
		}
		accepted := false
		p.once.Do(func() { accepted = true; p.done <- &a })
		if !accepted {
			http.Error(w, "already answered", http.StatusConflict)
			return
		}
		if a.Held == nil {
			// the phone takes its own notification down as it answers: no silent "clear" push for it
			if pn := s.session.notifier(); pn != nil {
				pn.answeredBy(dev)
			}
		}
		if a.Held != nil {
			logf("request %s: %q holds YubiKey %d, which this request is not for", p.req.Code, dev.Name, a.Held.Serial)
		} else {
			logf("request %s: answered by %q (declined=%v, results=%d)", p.req.Code, dev.Name, a.Declined, len(a.Results))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// The paired phone switches notifications on or off whenever the bridge is listening (a pair,
	// a test or a decrypt): signed by its Secure Enclave key, like every answer.
	mux.HandleFunc("POST /v1/device", func(w http.ResponseWriter, r *http.Request) {
		dev := s.device(r)
		if dev == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Push      *pushSettings `json:"push"`
			Signature string        `json:"signature"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.Push != nil && !body.Push.valid() {
			http.Error(w, "bad push settings", http.StatusBadRequest)
			return
		}
		if err := verifySigned(dev, deviceMessage(body.Push), body.Signature); err != nil {
			http.Error(w, "signature rejected", http.StatusForbidden)
			return
		}
		cfg, err := loadConfig()
		if err != nil {
			http.Error(w, "config", http.StatusInternalServerError)
			return
		}
		resp := map[string]string{}
		for i := range cfg.Devices {
			if !bytes.Equal(cfg.Devices[i].PublicKey, dev.PublicKey) {
				continue
			}
			if body.Push == nil {
				cfg.Devices[i].Push = nil
			} else {
				cfg.Devices[i].Push = newPushConfig(body.Push)
				resp["notify_key"] = base64.RawStdEncoding.EncodeToString(cfg.Devices[i].Push.NotifyKey)
			}
			dev.Push = cfg.Devices[i].Push
		}
		if err := cfg.save(); err != nil {
			http.Error(w, "config", http.StatusInternalServerError)
			return
		}
		logf("device %q: notifications %s", dev.Name, map[bool]string{true: "on", false: "off"}[body.Push != nil])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("POST /v1/pair", func(w http.ResponseWriter, r *http.Request) {
		if s.pair == nil {
			http.NotFound(w, r)
			return
		}
		s.pair(w, r)
	})
	return mux
}

// listen binds the configured address, retrying until the deadline: a second decrypt started
// while one is still waiting for the phone queues behind it instead of failing.
func listen(ctx context.Context, addr string, cert tls.Certificate) (net.Listener, error) {
	tcfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return tls.NewListener(ln, tcfg), nil
		}
		if !errors.Is(err, syscallEADDRINUSE) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("another KeyTap request is still waiting for the phone")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func serve(ln net.Listener, h http.Handler) *http.Server {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(ln)
	return srv
}
