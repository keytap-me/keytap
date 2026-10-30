package main

// A minimal APNs provider client: token-based auth (ES256 JWT, refreshed every 40 minutes) over
// HTTP/2, standard library only.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var apnsHosts = map[string]string{
	"production": "https://api.push.apple.com",
	"sandbox":    "https://api.sandbox.push.apple.com",
}

type apnsClient struct {
	key    *ecdsa.PrivateKey
	keyID  string
	teamID string
	topic  string
	http   *http.Client
	hosts  map[string]string

	mu     sync.Mutex
	jwt    string
	issued time.Time
}

func newAPNsClient(pemBytes []byte, keyID, teamID, topic string) (*apnsClient, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an EC private key")
	}
	tr := &http.Transport{ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 5 * time.Minute}
	return &apnsClient{key: ec, keyID: keyID, teamID: teamID, topic: topic,
		http: &http.Client{Transport: tr, Timeout: 10 * time.Second}, hosts: apnsHosts}, nil
}

func (c *apnsClient) token() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" && time.Since(c.issued) < 40*time.Minute {
		return c.jwt, nil
	}
	enc := base64.RawURLEncoding
	now := time.Now()
	header := enc.EncodeToString([]byte(`{"alg":"ES256","kid":"` + c.keyID + `"}`))
	claims := enc.EncodeToString([]byte(`{"iss":"` + c.teamID + `","iat":` + strconv.FormatInt(now.Unix(), 10) + `}`))
	digest := sha256.Sum256([]byte(header + "." + claims))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	c.jwt = header + "." + claims + "." + enc.EncodeToString(sig)
	c.issued = now
	return c.jwt, nil
}

// sendAlert: a visible notification with generic text; mutable-content lets the app's
// Notification Service Extension decrypt "k" and replace the text with the real summary.
func (c *apnsClient) sendAlert(ctx context.Context, n notifyReq) (int, error) {
	body := map[string]any{
		"aps": map[string]any{
			"alert":           map[string]string{"title": "Decryption request", "body": "Open KeyTap to review it."},
			"sound":           "default",
			"mutable-content": 1,
			"thread-id":       "keytap",
		},
		"k": n.Payload,
		"r": n.ID,
	}
	return c.send(ctx, n, body, "alert", "10", strconv.FormatInt(n.Expires, 10))
}

// sendClear: a silent push that tells the app to remove the notification for request id.
func (c *apnsClient) sendClear(ctx context.Context, n notifyReq) (int, error) {
	body := map[string]any{"aps": map[string]any{"content-available": 1}, "clear": n.ID}
	return c.send(ctx, n, body, "background", "5", strconv.FormatInt(time.Now().Add(2*time.Minute).Unix(), 10))
}

func (c *apnsClient) send(ctx context.Context, n notifyReq, body any, pushType, priority, expiration string) (int, error) {
	host, ok := c.hosts[n.Env]
	if !ok {
		return 0, fmt.Errorf("unknown env")
	}
	jwt, err := c.token()
	if err != nil {
		return 0, err
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host+"/3/device/"+n.Token, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", c.topic)
	req.Header.Set("apns-push-type", pushType)
	req.Header.Set("apns-priority", priority)
	req.Header.Set("apns-expiration", expiration)
	req.Header.Set("apns-collapse-id", n.ID)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, nil
}
