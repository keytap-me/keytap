package main

// On-disk state, all under $KEYTAP_DIR (default ~/.secure/keytap, mode 0700):
//   tls.crt / tls.key   the bridge's self-signed P-256 certificate; the phone pins its SHA-256
//   bridge.json         listen address + the paired devices (Secure Enclave public key, token hash)
//   bridge.log          request metadata only — never a file key, never a stanza body
// Nothing here can decrypt anything: the file keys only ever exist in this process's memory.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultListen = ":8743"

type Device struct {
	Name        string      `json:"name"`
	PublicKey   []byte      `json:"public_key"` // X9.63 uncompressed P-256 point (Secure Enclave)
	TokenSHA256 []byte      `json:"token_sha256"`
	PairedAt    time.Time   `json:"paired_at"`
	Keys        []YubiKey   `json:"yubikeys"`       // the YubiKeys registered with this phone at pairing
	Push        *PushConfig `json:"push,omitempty"` // set only if the phone opted in to notifications
}

// YubiKey is a key the phone registered by tapping it during pairing. Only requests for a
// registered key go to the phone; any other key is answered "not here" at once, the way
// age-plugin-yubikey skips an absent key (sops starts the plugin once per recipient).
type YubiKey struct {
	Serial    uint32 `json:"serial"`
	Slot      uint8  `json:"slot"`
	Recipient []byte `json:"recipient"` // 33-byte SEC1 compressed P-256 point
}

func (k YubiKey) tag() string {
	sum := sha256.Sum256(k.Recipient)
	return base64.RawStdEncoding.EncodeToString(sum[:4])
}

// registeredTags is the set of identity tags the paired phones can answer for.
func (c *Config) registeredTags() map[string]bool {
	tags := map[string]bool{}
	for _, d := range c.Devices {
		for _, k := range d.Keys {
			tags[k.tag()] = true
		}
	}
	return tags
}

type Config struct {
	Name      string   `json:"name,omitempty"`       // how the phone calls this computer (pair --name)
	PushRelay string   `json:"push_relay,omitempty"` // notification relay (default https://push.keytap.me)
	Listen    string   `json:"listen"`
	Devices   []Device `json:"devices"`
}

// displayName is what the phone shows for this computer: the pair --name, else the short
// hostname (no domain — the phone needs a label, not the network's naming scheme).
func (c *Config) displayName() string {
	if c.Name != "" {
		return c.Name
	}
	h, _ := os.Hostname()
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

func stateDir() string {
	if d := os.Getenv("KEYTAP_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secure", "keytap")
}

func loadConfig() (*Config, error) {
	c := &Config{Listen: defaultListen}
	b, err := os.ReadFile(filepath.Join(stateDir(), "bridge.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("bridge.json: %w", err)
	}
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	return c, nil
}

func (c *Config) save() error {
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := filepath.Join(stateDir(), "bridge.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir(), "bridge.json"))
}

// loadOrCreateCert returns the bridge certificate and the SHA-256 of its DER encoding (the pin).
func loadOrCreateCert() (tls.Certificate, [32]byte, error) {
	dir := stateDir()
	crtPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if cert, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
		return cert, sha256.Sum256(cert.Certificate[0]), nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "keytap-bridge " + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	return cert, sha256.Sum256(der), err
}

func logf(format string, args ...any) {
	f, err := os.OpenFile(filepath.Join(stateDir(), "bridge.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [%d] %s\n", time.Now().Format(time.RFC3339), os.Getpid(), fmt.Sprintf(format, args...))
}
