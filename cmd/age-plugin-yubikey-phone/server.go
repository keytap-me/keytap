package main

// The HTTPS endpoint the phone polls. It only exists while a decrypt is waiting for approval
// (or while `pair` runs): the phone CONNECTS OUT to it, and a refused connection simply means
// "nothing to approve". The bridge never connects to the phone.
//
//   GET  /v1/pending   Bearer → 200 the request JSON | 204 nothing pending
//   POST /v1/answer    Bearer + Secure-Enclave signature over the displayed request bytes
//   POST /v1/pair      one-time pairing code → registers the device key, returns its token (pair mode only)

import (
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
	mu      sync.Mutex
	pending *pending
	pair    func(w http.ResponseWriter, r *http.Request) // nil outside pair mode
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
		s.mu.Lock()
		p := s.pending
		s.mu.Unlock()
		if p == nil || time.Now().After(p.req.ExpiresAt) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
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
		s.mu.Lock()
		p := s.pending
		s.mu.Unlock()
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
		if p.check != nil && !a.Declined {
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
		logf("request %s: answered by %q (declined=%v, results=%d)", p.req.Code, dev.Name, a.Declined, len(a.Results))
		w.WriteHeader(http.StatusNoContent)
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
