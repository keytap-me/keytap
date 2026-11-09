package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPushIsEndToEndEncryptedAndCleared(t *testing.T) {
	t.Setenv("KEYTAP_DIR", t.TempDir())
	var mu sync.Mutex
	var calls []map[string]any
	var paths []string
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		calls, paths = append(calls, m), append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer relay.Close()
	t.Setenv("KEYTAP_PUSH_RELAY", relay.URL)

	push := newPushConfig(&pushSettings{Token: strings.Repeat("ab", 32), Env: "sandbox"})
	cfg := &Config{Devices: []Device{{Name: "phone", Push: push}, {Name: "no-push"}}}
	req := &Request{ID: "req-1", Code: "ABC-DEF", Host: "workstation", User: "demo",
		Command: "sops -d secrets/production.enc.yaml", Note: "rotate the db password", ExpiresAt: time.Now().Add(2 * time.Minute)}

	pn := notifyPhones(cfg, req)
	pn.clear()

	if len(calls) != 2 || paths[0] != "/v1/notify" || paths[1] != "/v1/clear" {
		t.Fatalf("relay calls: %v", paths)
	}
	n := calls[0]
	raw, _ := json.Marshal(n)
	for _, secret := range []string{"sops", "production", "workstation", "demo", "ABC-DEF"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the relay saw %q in plaintext", secret)
		}
	}
	if n["token"] != push.Token || n["env"] != "sandbox" || n["id"] != "req-1" {
		t.Errorf("notify fields: %v", n)
	}
	sealed, _ := base64.StdEncoding.DecodeString(n["payload"].(string))
	block, _ := aes.NewCipher(push.NotifyKey)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, sealed[:12], sealed[12:], []byte("req-1"))
	if err != nil {
		t.Fatalf("phone could not decrypt: %v", err)
	}
	// Even encrypted, a push carries no request details: only that something waits, and until when.
	for _, detail := range []string{"sops", "production", "workstation", "demo", "ABC-DEF", "rotate"} {
		if strings.Contains(string(plain), detail) {
			t.Errorf("the push summary contains %q: %s", detail, plain)
		}
	}
	var sum notificationSummary
	json.Unmarshal(plain, &sum)
	if sum.V != 2 || sum.ID != "req-1" || sum.Expires != req.ExpiresAt.Unix() {
		t.Errorf("summary: %+v", sum)
	}
	if _, err := gcm.Open(nil, sealed[:12], sealed[12:], []byte("other-request")); err == nil {
		t.Errorf("ciphertext must be bound to its request id")
	}
	if calls[1]["id"] != "req-1" || calls[1]["payload"] != nil {
		t.Errorf("clear: %v", calls[1])
	}
}

// The phone that answers removes its own notification; the silent clear goes only to the others.
func TestClearSkipsThePhoneThatAnswered(t *testing.T) {
	t.Setenv("KEYTAP_DIR", t.TempDir())
	var mu sync.Mutex
	var clears []string
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		if r.URL.Path == "/v1/clear" {
			mu.Lock()
			clears = append(clears, m["token"].(string))
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer relay.Close()
	t.Setenv("KEYTAP_PUSH_RELAY", relay.URL)

	a := Device{Name: "answered", PublicKey: []byte{1}, Push: newPushConfig(&pushSettings{Token: strings.Repeat("aa", 32), Env: "sandbox"})}
	b := Device{Name: "other", PublicKey: []byte{2}, Push: newPushConfig(&pushSettings{Token: strings.Repeat("bb", 32), Env: "sandbox"})}
	cfg := &Config{Devices: []Device{a, b}}
	pn := notifyPhones(cfg, &Request{ID: "req-2", ExpiresAt: time.Now().Add(time.Minute)})
	pn.answeredBy(&cfg.Devices[0])
	pn.clear()
	if len(clears) != 1 || clears[0] != b.Push.Token {
		t.Errorf("clear pushes went to %v; want only the phone that did not answer", clears)
	}
}

func TestGoneTokenTurnsPushOff(t *testing.T) {
	t.Setenv("KEYTAP_DIR", t.TempDir())
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) }))
	defer relay.Close()
	t.Setenv("KEYTAP_PUSH_RELAY", relay.URL)
	cfg := &Config{Listen: "127.0.0.1:1", Devices: []Device{{Name: "phone", Push: newPushConfig(&pushSettings{Token: strings.Repeat("cd", 32), Env: "production"})}}}
	cfg.save()
	notifyPhones(cfg, &Request{ID: "r", ExpiresAt: time.Now().Add(time.Minute)})
	again, _ := loadConfig()
	if again.Devices[0].Push != nil {
		t.Errorf("a token APNs rejects must switch notifications off")
	}
}

func TestDeviceMessageCanonical(t *testing.T) {
	if string(deviceMessage(nil)) != "keytap-device-v1\npush off\n" {
		t.Error("off message")
	}
	if string(deviceMessage(&pushSettings{Token: "ABCD", Env: "sandbox"})) != "keytap-device-v1\npush abcd sandbox\n" {
		t.Error("on message")
	}
}
