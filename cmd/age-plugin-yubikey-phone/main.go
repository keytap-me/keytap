// age-plugin-yubikey-phone — the KeyTap workstation bridge.
//
// Speaks the age plugin protocol in place of age-plugin-yubikey, but performs the YubiKey's
// part on the user's iPhone: the stanza goes to the phone, the phone verifies the PIN and
// runs the ECDH on the key tapped against it, unwraps, and returns only the 16-byte file key.
//
//	age-plugin-yubikey-phone --age-plugin=identity-v1   decrypt (what age / sops run)
//	age-plugin-yubikey-phone pair --host IP [--port 8743] [--recipient age1yubikey1…]
//	age-plugin-yubikey-phone test [--serial N] [--note TEXT]   dry run through the phone: PIN + tap + ECDH, nothing decrypted
//	age-plugin-yubikey-phone devices | unpair NAME | version
//
// KEYTAP_NOTE="…" in the environment of a decrypt (e.g. `KEYTAP_NOTE="rotate the db password" sops -d f`)
// is shown at the top of the request on the phone: the requester's own words, not verified.
//
// Encryption (recipient-v1) and every other age-plugin-yubikey command need no YubiKey
// secret and are handed to the real plugin unchanged.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// version is set at release build time (-ldflags "-X main.version=vX.Y.Z").
var version = "dev"

func main() {
	args := os.Args[1:]
	var err error
	switch {
	case len(args) > 0 && args[0] == "--age-plugin=identity-v1":
		err = runIdentityPlugin(os.Stdin, os.Stdout)
	case len(args) > 0 && args[0] == "pair":
		err = runPair(args[1:])
	case len(args) > 0 && (args[0] == "version" || args[0] == "--version"):
		fmt.Println("age-plugin-yubikey-phone", version)
	case len(args) > 0 && args[0] == "test":
		err = runTest(args[1:])
	case len(args) > 0 && args[0] == "devices":
		err = runDevices()
	case len(args) == 2 && args[0] == "unpair":
		err = runUnpair(args[1])
	default:
		err = execRealPlugin(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keytap:", err)
		os.Exit(1)
	}
}

func execRealPlugin(args []string) error {
	real := findRealPlugin()
	if real == "" {
		return fmt.Errorf("no age-plugin-yubikey found to handle %q", strings.Join(args, " "))
	}
	return runReal(real, args)
}

// findRealPlugin locates the real age-plugin-yubikey: the usual install locations first, then
// every PATH entry — skipping this program itself, which may be installed under that very name
// (the "shim": ahead of the real plugin on PATH, so age asks the phone).
func findRealPlugin() string {
	name := "age-plugin-yubikey" + exeSuffix
	self, _ := os.Executable()
	if r, err := filepath.EvalSymlinks(self); err == nil {
		self = r
	}
	selfInfo, _ := os.Stat(self)
	home, _ := os.UserHomeDir()
	candidates := []string{"/opt/homebrew/bin/" + name, "/usr/local/bin/" + name, filepath.Join(home, ".cargo", "bin", name)}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir != "" {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}
	for _, c := range candidates {
		r, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		st, err := os.Stat(r)
		if err != nil || st.IsDir() || (exeSuffix == "" && st.Mode()&0o111 == 0) {
			continue
		}
		if selfInfo != nil && os.SameFile(st, selfInfo) {
			continue
		}
		return r
	}
	return ""
}
