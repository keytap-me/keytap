package main

// Optional notifications (opt-in per phone). When a decrypt waits, the bridge asks the relay
// (push.keytap.me unless configured otherwise) to wake the paired phone through Apple's push
// service, and to remove the notification again when the request is answered or expires.
//
// The relay and Apple see the phone's push token, the time, the random request id and ciphertext:
// the summary (computer, user, command, code, expiry) is AES-256-GCM-encrypted under a key that
// only this bridge and the phone hold (created when notifications are switched on), with the
// request id as additional data. Without a phone that opted in, nothing is sent anywhere.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultPushRelay = "https://push.keytap.me"

// PushConfig is stored per paired device when the phone opted in to notifications.
type PushConfig struct {
	Token     string `json:"token"`      // APNs device token, hex
	Env       string `json:"env"`        // "production" (App Store/TestFlight) or "sandbox" (development builds)
	NotifyKey []byte `json:"notify_key"` // 32 bytes, AES-256-GCM, shared with the phone only
}

type pushSettings struct {
	Token string `json:"token"`
	Env   string `json:"env"`
}

func (p *pushSettings) valid() bool {
	if p == nil || len(p.Token) < 64 || len(p.Token) > 200 || (p.Env != "production" && p.Env != "sandbox") {
		return false
	}
	_, err := hex.DecodeString(p.Token)
	return err == nil
}

func newPushConfig(p *pushSettings) *PushConfig {
	key := make([]byte, 32)
	rand.Read(key)
	return &PushConfig{Token: strings.ToLower(p.Token), Env: p.Env, NotifyKey: key}
}

func (c *Config) pushRelay() string {
	if v := os.Getenv("KEYTAP_PUSH_RELAY"); v != "" {
		return strings.TrimRight(v, "/")
	}
	if c.PushRelay != "" {
		return strings.TrimRight(c.PushRelay, "/")
	}
	return defaultPushRelay
}

// notificationSummary is what the phone shows in the notification once it has decrypted it.
type notificationSummary struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	Kind    string `json:"kind,omitempty"`
	Code    string `json:"code"`
	Host    string `json:"host"`
	User    string `json:"user"`
	Command string `json:"cmd"`
	Note    string `json:"note,omitempty"`
	Expires int64  `json:"exp"`
}

func sealSummary(key []byte, req *Request) (string, error) {
	cmd := req.Command
	if len(cmd) > 160 {
		cmd = cmd[:160] + "…"
	}
	plain, _ := json.Marshal(notificationSummary{V: 1, ID: req.ID, Kind: req.Kind, Code: req.Code, Host: req.Host,
		User: req.User, Command: cmd, Note: truncateRunes(req.Note, maxPushNote), Expires: req.ExpiresAt.Unix()})
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	sealed := gcm.Seal(nonce, nonce, plain, []byte(req.ID))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

var pushHTTP = &http.Client{Timeout: 6 * time.Second}

// errTokenGone: the relay says Apple no longer accepts this token (app removed, notifications off).
var errTokenGone = errors.New("push token no longer valid")

func relayCall(ctx context.Context, relay, path string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, relay+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pushHTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusGone:
		return errTokenGone
	default:
		return fmt.Errorf("relay answered %d", resp.StatusCode)
	}
}

// pushNotifier wakes every opted-in phone for one request and clears the notification afterwards.
type pushNotifier struct {
	cfg  *Config
	req  *Request
	mu   sync.Mutex
	sent []*Device
}

func notifyPhones(cfg *Config, req *Request) *pushNotifier {
	n := &pushNotifier{cfg: cfg, req: req}
	var wg sync.WaitGroup
	for i := range cfg.Devices {
		d := &cfg.Devices[i]
		if d.Push == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, err := sealSummary(d.Push.NotifyKey, req)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			err = relayCall(ctx, cfg.pushRelay(), "/v1/notify", map[string]any{
				"token": d.Push.Token, "env": d.Push.Env, "id": req.ID, "payload": payload, "expires": req.ExpiresAt.Unix()})
			switch {
			case err == nil:
				n.mu.Lock()
				n.sent = append(n.sent, d)
				n.mu.Unlock()
				logf("request %s: notified %q", req.Code, d.Name)
			case errors.Is(err, errTokenGone):
				logf("request %s: %q's push token is gone; notifications for it are off until it re-enables them", req.Code, d.Name)
				dropPush(d.Name)
			default:
				logf("request %s: notification to %q failed: %v (polling still works)", req.Code, d.Name, err)
			}
		}()
	}
	wg.Wait()
	return n
}

// clear removes the notification on every phone that got one (answered, declined or expired).
func (n *pushNotifier) clear() {
	n.mu.Lock()
	sent := n.sent
	n.mu.Unlock()
	for _, d := range sent {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		relayCall(ctx, n.cfg.pushRelay(), "/v1/clear", map[string]any{"token": d.Push.Token, "env": d.Push.Env, "id": n.req.ID})
		cancel()
	}
}

// dropPush turns notifications off for one device in the stored config.
func dropPush(name string) {
	cfg, err := loadConfig()
	if err != nil {
		return
	}
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			cfg.Devices[i].Push = nil
		}
	}
	cfg.save()
}
