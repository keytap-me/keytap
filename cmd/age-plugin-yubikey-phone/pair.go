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
	"os"
	"strings"
	"sync"
	"time"
)

type pairBody struct {
	Code       string        `json:"code"`
	DeviceName string        `json:"device_name"`
	PublicKey  string        `json:"public_key"`     // base64 X9.63 uncompressed P-256 point
	Push       *pushSettings `json:"push,omitempty"` // optional: notifications through the relay
}

func runPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	host := fs.String("host", "", "IP address the iPhone reaches this Mac at (required)")
	port := fs.String("port", "", "port (default 8743 or the stored one); the listener binds --host only")
	nameFlag := fs.String("name", "", "how the phone shows this computer (default: short hostname)")
	noQR := fs.Bool("no-qr", false, "do not draw the link as a QR code")
	relayFlag := fs.String("push-relay", "", "notification relay for phones that opt in (default "+defaultPushRelay+")")
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
	if *relayFlag != "" {
		cfg.PushRelay = strings.TrimSpace(*relayFlag)
	}
	name := cfg.displayName()

	q := url.Values{}
	q.Set("v", "1")
	q.Set("host", cfg.Listen)
	q.Set("fp", base64.RawURLEncoding.EncodeToString(pin[:]))
	q.Set("code", code)
	q.Set("name", name)
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
		tok := make([]byte, 32)
		rand.Read(tok)
		token := base64.RawURLEncoding.EncodeToString(tok)
		sum := sha256.Sum256([]byte(token))
		devName := strings.TrimSpace(b.DeviceName)
		if devName == "" || len(devName) > 64 {
			devName = "iPhone"
		}
		dev := Device{Name: devName, PublicKey: pub, TokenSHA256: sum[:], PairedAt: time.Now().UTC()}
		resp := map[string]string{"token": token, "bridge_name": name}
		if b.Push.valid() {
			dev.Push = newPushConfig(b.Push)
			resp["notify_key"] = base64.RawStdEncoding.EncodeToString(dev.Push.NotifyKey)
		}
		paired <- dev
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
	srv := serve(ln, s.handler())
	defer srv.Close()

	// In a terminal: the link as a QR code — the iPhone's camera opens it in KeyTap, nothing to copy.
	if !*noQR && isTerminal(os.Stdout) && printQR(os.Stdout, link, "  ") == nil {
		fmt.Printf("\nScan this with the iPhone's camera and tap \"Open in KeyTap\" — or copy the link and paste it into KeyTap:\n\n  %s\n\n", link)
	} else {
		fmt.Printf("Open this link on the iPhone (copy it from the terminal, then paste it into KeyTap):\n\n  %s\n\n", link)
	}
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
		if d.Push != nil {
			fmt.Printf("  Notifications: on, via %s (end-to-end encrypted)\n", cfg.pushRelay())
		}
		printKeys()
		fmt.Println("Next: `age-plugin-yubikey-phone test` runs a dry run through the phone.")
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
		if d.Push != nil {
			fmt.Printf("    notifications: on (%s)\n", d.Push.Env)
		}
	}
	printKeys()
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

// printKeys lists the YubiKeys this computer offers the phone (keys.conf + the identity file). The phone
// stores none of them: change the files, and the next request carries the new list.
func printKeys() {
	keys := knownKeys()
	if len(keys) == 0 {
		fmt.Printf("YubiKeys: none found (%s, %s). Requests then offer only the keys age passes in.\n", keysConfPath(), identityFilePath())
		return
	}
	fmt.Println("YubiKeys offered to the phone:")
	for _, k := range keys {
		extra := ""
		if len(k.SSH) > 0 {
			extra = fmt.Sprintf(", %d ssh key(s)", len(k.SSH))
		}
		fmt.Printf("  %-16s %d%s\n", k.Label, k.Serial, extra)
	}
}
