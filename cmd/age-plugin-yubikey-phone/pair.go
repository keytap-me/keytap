package main

// `age-plugin-yubikey-phone pair --host IP` — register the phone. The bridge then listens on
// that address only (never 0.0.0.0: the workstation sits on many VLANs). Prints a keytap:// link carrying the
// bridge address, the certificate pin and a one-time code; the app opens it, creates its
// Secure Enclave key and posts the public half. One device per run; the window closes after
// the first pairing or ten minutes.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type pairBody struct {
	Code       string `json:"code"`
	DeviceName string `json:"device_name"`
	PublicKey  string `json:"public_key"` // base64 X9.63 uncompressed P-256 point
	YubiKeys   []struct {
		Serial    uint32 `json:"serial"`
		Slot      uint8  `json:"slot"`
		Recipient string `json:"recipient"` // base64, 33 bytes compressed
	} `json:"yubikeys"`
}

func runPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	host := fs.String("host", "", "IP address the iPhone reaches this Mac at (required)")
	port := fs.String("port", "", "port (default 8743 or the stored one); the listener binds --host only")
	recipient := fs.String("recipient", "", "age1yubikey1… recipient to show on the phone (optional, public)")
	nameFlag := fs.String("name", "", "how the phone shows this computer (default: short hostname)")
	fs.Parse(args)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("pass --host: the address this Mac is reached at from the iPhone (the listener binds it, and only it)")
	}
	if net.ParseIP(*host) == nil {
		return fmt.Errorf("--host %q is not an IP address", *host)
	}
	if *port == "" {
		_, *port, _ = net.SplitHostPort(cfg.Listen)
	}
	if *port == "" {
		_, *port, _ = net.SplitHostPort(defaultListen)
	}
	cfg.Listen = net.JoinHostPort(*host, *port)
	cert, pin, err := loadOrCreateCert()
	if err != nil {
		return err
	}
	codeBytes := make([]byte, 16)
	rand.Read(codeBytes)
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	if *nameFlag != "" {
		cfg.Name = strings.TrimSpace(*nameFlag)
	}
	name := cfg.displayName()

	q := url.Values{}
	q.Set("v", "1")
	q.Set("host", cfg.Listen)
	q.Set("fp", base64.RawURLEncoding.EncodeToString(pin[:]))
	q.Set("code", code)
	q.Set("name", name)
	if *recipient != "" {
		q.Set("recipient", *recipient)
	}
	link := "keytap://pair?" + q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ln, err := listen(ctx, cfg.Listen, cert)
	if err != nil {
		return err
	}
	paired := make(chan Device, 1)
	var used sync.Once
	s := &server{cfg: cfg}
	s.pair = func(w http.ResponseWriter, r *http.Request) {
		var b pairBody
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pub, err := b64any(b.PublicKey)
		if subtle.ConstantTimeCompare([]byte(b.Code), []byte(code)) != 1 || err != nil || len(pub) != 65 || pub[0] != 4 {
			http.Error(w, "pairing refused", http.StatusForbidden)
			return
		}
		ok := false
		used.Do(func() { ok = true })
		if !ok {
			http.Error(w, "pairing code already used", http.StatusConflict)
			return
		}
		var keys []YubiKey
		for _, k := range b.YubiKeys {
			r, err := b64any(k.Recipient)
			if err != nil || len(r) != 33 || decompressP256(r) == nil || k.Slot < 0x82 || k.Slot > 0x95 {
				http.Error(w, "invalid YubiKey registration", http.StatusBadRequest)
				return
			}
			keys = append(keys, YubiKey{Serial: k.Serial, Slot: k.Slot, Recipient: r})
		}
		tok := make([]byte, 32)
		rand.Read(tok)
		token := base64.RawURLEncoding.EncodeToString(tok)
		sum := sha256.Sum256([]byte(token))
		devName := strings.TrimSpace(b.DeviceName)
		if devName == "" || len(devName) > 64 {
			devName = "iPhone"
		}
		paired <- Device{Name: devName, PublicKey: pub, TokenSHA256: sum[:], PairedAt: time.Now().UTC(), Keys: keys}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token, "bridge_name": name})
	}
	srv := serve(ln, s.handler())
	defer srv.Close()

	fmt.Printf("Open this link on the iPhone (copy it from the terminal, then paste it into KeyTap):\n\n  %s\n\n", link)
	fmt.Printf("Waiting up to 10 minutes on %s …\n", cfg.Listen)
	select {
	case d := <-paired:
		kept := cfg.Devices[:0]
		for _, old := range cfg.Devices {
			if old.Name != d.Name {
				kept = append(kept, old)
			}
		}
		cfg.Devices = append(kept, d)
		if err := cfg.save(); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond) // let the response reach the phone before closing
		fmt.Printf("Paired %q.\n", d.Name)
		for _, k := range d.Keys {
			fmt.Printf("  YubiKey %d, slot %#x: %s\n", k.Serial, k.Slot, bech32Encode("age1yubikey", k.Recipient))
		}
		if len(d.Keys) > 0 {
			fmt.Println("Next: `age-plugin-yubikey-phone test` runs a dry run through the phone.")
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("pairing window closed without a device")
	}
}

func runDevices() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Devices) == 0 {
		fmt.Println("no paired devices")
	}
	for _, d := range cfg.Devices {
		sum := sha256.Sum256(d.PublicKey)
		fmt.Printf("%-24s paired %s  device key %x\n", d.Name, d.PairedAt.Local().Format("2006-01-02 15:04"), sum[:6])
		for _, k := range d.Keys {
			fmt.Printf("    YubiKey %d, slot %#x: %s\n", k.Serial, k.Slot, bech32Encode("age1yubikey", k.Recipient))
		}
	}
	return nil
}

func runUnpair(name string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	kept := cfg.Devices[:0]
	for _, d := range cfg.Devices {
		if d.Name != name {
			kept = append(kept, d)
		}
	}
	if len(kept) == len(cfg.Devices) {
		return fmt.Errorf("no device named %q", name)
	}
	cfg.Devices = kept
	return cfg.save()
}
