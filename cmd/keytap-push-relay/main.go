// keytap-push-relay — the optional notification relay behind push.keytap.me.
//
// A KeyTap bridge that the user has opted in to notifications asks the relay to wake the paired
// iPhone. The relay forwards that to Apple Push Notification service (APNs) and forgets it.
//
//	POST /v1/notify  {"token","env","id","payload","expires"}  → an alert push the phone decrypts
//	POST /v1/clear   {"token","env","id"}                      → a silent push that removes it again
//	GET  /healthz
//
// What the relay can see: the phone's APNs device token, the time, the request id (random) and an
// opaque payload. The payload is AES-256-GCM ciphertext under a key only the bridge and the phone
// share (from pairing); the relay and Apple cannot read it. The relay stores nothing — no database,
// no files — and logs no tokens or payloads, only counts and APNs status codes. It can only reach
// the KeyTap app (one fixed APNs topic) and rate-limits per token and per client address.
//
// Configuration (environment): APNS_KEY_FILE (the .p8 auth key), APNS_KEY_ID, APNS_TEAM_ID,
// APNS_TOPIC (default me.keytap.app), PORT (default 8080), TRUST_PROXY=1 to rate-limit by
// the last X-Forwarded-For entry (only behind a proxy that appends it).
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxBody    = 4 << 10
	maxPayload = 2048 // base64 chars; APNs allows 4 KB in total
	maxTTL     = 10 * time.Minute
)

type notifyReq struct {
	Token   string `json:"token"`
	Env     string `json:"env"`
	ID      string `json:"id"`
	Payload string `json:"payload"`
	Expires int64  `json:"expires"`
}

type relay struct {
	apns     *apnsClient
	perToken *limiter
	perIP    *limiter
	trustXFF bool
	stats    struct{ notify, clear, rejected, apnsErr atomic.Int64 }
}

func main() {
	keyFile, keyID, teamID := os.Getenv("APNS_KEY_FILE"), os.Getenv("APNS_KEY_ID"), os.Getenv("APNS_TEAM_ID")
	topic := envOr("APNS_TOPIC", "me.keytap.app")
	if keyFile == "" || keyID == "" || teamID == "" {
		log.Fatal("APNS_KEY_FILE, APNS_KEY_ID and APNS_TEAM_ID are required")
	}
	pem, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("read APNs key: %v", err)
	}
	client, err := newAPNsClient(pem, keyID, teamID, topic)
	if err != nil {
		log.Fatalf("APNs key: %v", err)
	}
	r := &relay{
		apns:     client,
		perToken: newLimiter(10, time.Minute),
		perIP:    newLimiter(120, time.Minute),
		trustXFF: os.Getenv("TRUST_PROXY") == "1",
	}
	go r.report()
	srv := &http.Server{
		Addr:              ":" + envOr("PORT", "8080"),
		Handler:           r.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Printf("keytap-push-relay listening on %s (topic %s)", srv.Addr, topic)
	log.Fatal(srv.ListenAndServe())
}

func (r *relay) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("POST /v1/notify", func(w http.ResponseWriter, req *http.Request) { r.handle(w, req, true) })
	mux.HandleFunc("POST /v1/clear", func(w http.ResponseWriter, req *http.Request) { r.handle(w, req, false) })
	return mux
}

func (r *relay) handle(w http.ResponseWriter, req *http.Request, notify bool) {
	if !r.perIP.allow(r.clientIP(req)) {
		r.stats.rejected.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	var n notifyReq
	dec := json.NewDecoder(io.LimitReader(req.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&n); err != nil {
		r.stats.rejected.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := validate(&n, notify); err != nil {
		r.stats.rejected.Add(1)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !r.perToken.allow(n.Token) {
		r.stats.rejected.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	var status int
	var err error
	if notify {
		status, err = r.apns.sendAlert(ctx, n)
		r.stats.notify.Add(1)
	} else {
		status, err = r.apns.sendClear(ctx, n)
		r.stats.clear.Add(1)
	}
	switch {
	case err != nil:
		r.stats.apnsErr.Add(1)
		http.Error(w, "push service unavailable", http.StatusBadGateway)
	case status == http.StatusOK:
		w.WriteHeader(http.StatusNoContent)
	case status == http.StatusGone || status == http.StatusBadRequest:
		// 410: the app was removed or notifications turned off; 400: e.g. a token for the other
		// environment. Either way the bridge should stop using this token.
		r.stats.apnsErr.Add(1)
		http.Error(w, fmt.Sprintf("token rejected by APNs (%d)", status), http.StatusGone)
	default:
		r.stats.apnsErr.Add(1)
		http.Error(w, fmt.Sprintf("push service answered %d", status), http.StatusBadGateway)
	}
}

func validate(n *notifyReq, notify bool) error {
	if len(n.Token) < 64 || len(n.Token) > 200 {
		return errors.New("bad token")
	}
	if _, err := hex.DecodeString(n.Token); err != nil {
		return errors.New("bad token")
	}
	n.Token = strings.ToLower(n.Token)
	if n.Env != "production" && n.Env != "sandbox" {
		return errors.New("env must be production or sandbox")
	}
	if n.ID == "" || len(n.ID) > 64 || strings.Trim(n.ID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return errors.New("bad id")
	}
	if !notify {
		return nil
	}
	if n.Payload == "" || len(n.Payload) > maxPayload {
		return errors.New("bad payload")
	}
	if _, err := base64.StdEncoding.DecodeString(n.Payload); err != nil {
		return errors.New("payload must be base64")
	}
	now := time.Now()
	exp := time.Unix(n.Expires, 0)
	if exp.Before(now) || exp.After(now.Add(maxTTL)) {
		return errors.New("expires must be within the next 10 minutes")
	}
	return nil
}

func (r *relay) clientIP(req *http.Request) string {
	if r.trustXFF {
		// The proxy APPENDS the address it saw; everything before it is whatever the client claimed.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// report logs counters only — never a token, an id or a payload.
func (r *relay) report() {
	for range time.Tick(time.Hour) {
		log.Printf("last hour: notify=%d clear=%d rejected=%d apns_errors=%d",
			r.stats.notify.Swap(0), r.stats.clear.Swap(0), r.stats.rejected.Swap(0), r.stats.apnsErr.Swap(0))
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
