package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type seen struct {
	path, auth, topic, pushType, collapse string
	body                                  map[string]any
}

// fakeAPNs verifies the JWT against the public key and records what the relay sent.
func fakeAPNs(t *testing.T, pub *ecdsa.PublicKey, status int, got *[]seen) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("APNs requires HTTP/2, got %s", r.Proto)
		}
		jwt := strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatalf("bad jwt")
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Errorf("jwt signature does not verify")
		}
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		*got = append(*got, seen{r.URL.Path, jwt, r.Header.Get("apns-topic"), r.Header.Get("apns-push-type"), r.Header.Get("apns-collapse-id"), b})
		w.WriteHeader(status)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	return srv
}

func testRelay(t *testing.T, status int) (*relay, *[]seen, func()) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	c, err := newAPNsClient(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "KEYID12345", "TEAM123456", "me.keytap.app")
	if err != nil {
		t.Fatal(err)
	}
	got := &[]seen{}
	srv := fakeAPNs(t, &key.PublicKey, status, got)
	c.http = srv.Client()
	c.hosts = map[string]string{"production": srv.URL, "sandbox": srv.URL}
	return &relay{apns: c, perToken: newLimiter(3, time.Minute), perIP: newLimiter(100, time.Minute)}, got, srv.Close
}

func post(h http.Handler, path string, v any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(v)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return rec
}

var token = strings.Repeat("ab", 32)

func validNotify() map[string]any {
	return map[string]any{"token": token, "env": "production", "id": "req-123",
		"payload": base64.StdEncoding.EncodeToString([]byte("opaque ciphertext")), "expires": time.Now().Add(2 * time.Minute).Unix()}
}

func TestNotifyAndClear(t *testing.T) {
	r, got, done := testRelay(t, 200)
	defer done()
	h := r.routes()
	if rec := post(h, "/v1/notify", validNotify()); rec.Code != http.StatusNoContent {
		t.Fatalf("notify: %d %s", rec.Code, rec.Body)
	}
	if rec := post(h, "/v1/clear", map[string]any{"token": token, "env": "sandbox", "id": "req-123"}); rec.Code != http.StatusNoContent {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	if len(*got) != 2 {
		t.Fatalf("APNs saw %d requests", len(*got))
	}
	a, c := (*got)[0], (*got)[1]
	if a.path != "/3/device/"+token || a.topic != "me.keytap.app" || a.pushType != "alert" || a.collapse != "req-123" {
		t.Errorf("alert: %+v", a)
	}
	aps := a.body["aps"].(map[string]any)
	if aps["mutable-content"] != float64(1) || a.body["k"] == nil || a.body["r"] != "req-123" {
		t.Errorf("alert body: %v", a.body)
	}
	if fmt.Sprint(aps["alert"]) != "map[body:Open KeyTap to review it. title:Decryption request]" {
		t.Errorf("the alert text must stay generic (the summary is encrypted): %v", aps["alert"])
	}
	if c.pushType != "background" || c.body["clear"] != "req-123" {
		t.Errorf("clear: %+v", c)
	}
}

func TestRejectsBadInput(t *testing.T) {
	r, got, done := testRelay(t, 200)
	defer done()
	h := r.routes()
	bad := []func(m map[string]any){
		func(m map[string]any) { m["token"] = "short" },
		func(m map[string]any) { m["token"] = strings.Repeat("zz", 32) },
		func(m map[string]any) { m["env"] = "dev" },
		func(m map[string]any) { m["id"] = "has spaces" },
		func(m map[string]any) { m["payload"] = "%%%" },
		func(m map[string]any) { m["payload"] = strings.Repeat("A", 4000) },
		func(m map[string]any) { m["expires"] = time.Now().Add(-time.Minute).Unix() },
		func(m map[string]any) { m["expires"] = time.Now().Add(time.Hour).Unix() },
		func(m map[string]any) { m["extra"] = "field" },
	}
	for i, mut := range bad {
		m := validNotify()
		mut(m)
		if rec := post(h, "/v1/notify", m); rec.Code != http.StatusBadRequest {
			t.Errorf("case %d: got %d, want 400", i, rec.Code)
		}
	}
	if len(*got) != 0 {
		t.Errorf("invalid requests reached APNs")
	}
}

func TestRateLimitPerToken(t *testing.T) {
	r, _, done := testRelay(t, 200)
	defer done()
	h := r.routes()
	for i := 0; i < 3; i++ {
		if rec := post(h, "/v1/notify", validNotify()); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := post(h, "/v1/notify", validNotify()); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: %d, want 429", rec.Code)
	}
}

func TestGoneTokenIsReported(t *testing.T) {
	r, _, done := testRelay(t, 410)
	defer done()
	if rec := post(r.routes(), "/v1/notify", validNotify()); rec.Code != http.StatusGone {
		t.Fatalf("got %d, want 410", rec.Code)
	}
	_ = io.Discard
}

func TestClientIPIgnoresSpoofedForwardedFor(t *testing.T) {
	r := &relay{trustXFF: true}
	req := httptest.NewRequest(http.MethodPost, "/v1/notify", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := r.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("got %s, want the address the proxy appended", got)
	}
}
