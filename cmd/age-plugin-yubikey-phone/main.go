// age-plugin-yubikey-phone — the KeyTap workstation bridge.
//
// Speaks the age plugin protocol in place of age-plugin-yubikey, but performs the YubiKey's
// part on the user's iPhone: the stanza goes to the phone, the phone verifies the PIN and
// runs the ECDH on the key tapped against it, unwraps, and returns only the 16-byte file key.
// Any of the computer's YubiKeys answers, with one PIN and one tap per command (see chain.go).
//
//	age-plugin-yubikey-phone --age-plugin=identity-v1 [--session ID]   decrypt (what age / sops run)
//	age-plugin-yubikey-phone pair --host IP [--port 8743] [--name NAME]
//	age-plugin-yubikey-phone test [--key LABEL|SERIAL] [--note TEXT]   dry run: PIN + tap + ECDH, nothing decrypted
//	age-plugin-yubikey-phone devices | unpair NAME | version [--json]
//	age-plugin-yubikey-phone ssh-opts [key file…]   ssh arguments that send FIDO2 (ed25519-sk) signatures to the phone
//	age-plugin-yubikey-phone sk-sign [--session ID]  what keytap-sk.dylib (the OpenSSH security key provider) runs
//	age-plugin-yubikey-phone agent -a SOCK [--keys DIR] [--upstream SOCK]… [--label-from keys.conf]
//	                                                 an ssh-agent that signs through the phone (racing upstream agents)
//
// For a race router (start the phone request speculatively, ask other computers meanwhile):
//
//	hold --session ID          age's phase 1 on stdin; starts the phone request in the background, prints nothing
//	status --session ID [--wait MS]   pending (10) | engaged (11) | answered (12) | gone (13)
//	withdraw --session ID [--reason TEXT] [--force]   0 withdrawn or gone, 7 refused (open on the phone)
//
// KEYTAP_NOTE="…" in the environment of a decrypt (e.g. `KEYTAP_NOTE="rotate the db password" sops -d f`)
// is shown at the top of the request on the phone: the requester's own words, not verified.
//
// Encryption (recipient-v1) and every other age-plugin-yubikey command need no YubiKey
// secret and are handed to the real plugin unchanged.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// version is set at release build time (-ldflags "-X main.version=vX.Y.Z").
var version = "dev"

// takeFlag removes "--name value" / "--name=value" from args and returns the value ("" if absent).
func takeFlag(args []string, name string) ([]string, string, bool) {
	out := args[:0:0]
	val, found := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--"+name && i+1 < len(args):
			val, found = args[i+1], true
			i++
		case strings.HasPrefix(a, "--"+name+"="):
			val, found = strings.TrimPrefix(a, "--"+name+"="), true
		default:
			out = append(out, a)
		}
	}
	return out, val, found
}

func takeBool(args []string, name string) ([]string, bool) {
	out := args[:0:0]
	found := false
	for _, a := range args {
		if a == "--"+name {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// sessionFrom: --session, else $KEYTAP_SESSION (both explicit), else the fallback (the asking process).
func sessionFrom(args []string, fallback func() int) ([]string, string, bool, error) {
	args, id, explicit := takeFlag(args, "session")
	if !explicit {
		if v := os.Getenv("KEYTAP_SESSION"); v != "" {
			id, explicit = v, true
		} else if v := os.Getenv("KEYTAP_RACE"); v != "" {
			id, explicit = v, true
		}
	}
	if id == "" && fallback != nil {
		id = strconv.Itoa(fallback())
	}
	if id == "" {
		return args, "", explicit, fmt.Errorf("pass --session ID")
	}
	return args, id, explicit, validSession(id)
}

func main() {
	args := os.Args[1:]
	code, err := run(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keytap:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "--age-plugin=identity-v1":
		rest, id, explicit, err := sessionFrom(args[1:], os.Getppid)
		if err != nil {
			return 2, err
		}
		_ = rest
		return runIdentityPlugin(os.Stdin, os.Stdout, id, explicit)
	case "sk-sign":
		_, id, explicit, err := sessionFrom(args[1:], sshPID)
		if err != nil {
			return 2, err
		}
		return runSKSign(os.Stdin, os.Stdout, id, explicit)
	case "hold":
		_, id, _, err := sessionFrom(args[1:], nil)
		if err != nil {
			return 2, err
		}
		return runHold(id)
	case "status":
		rest, wait, _ := takeFlag(args[1:], "wait")
		rest, id, _, err := sessionFrom(rest, nil)
		if err != nil && len(rest) == 1 && validSession(rest[0]) == nil {
			id, err = rest[0], nil
		}
		if err != nil {
			return 2, err
		}
		ms, _ := strconv.Atoi(wait)
		return runStatus(id, ms), nil
	case "withdraw":
		rest, reason, _ := takeFlag(args[1:], "reason")
		rest, force := takeBool(rest, "force")
		rest, id, _, err := sessionFrom(rest, nil)
		if err != nil && len(rest) == 1 && validSession(rest[0]) == nil {
			id, err = rest[0], nil
		}
		if err != nil {
			return 2, err
		}
		return runWithdraw(id, reason, force), nil
	case "__holder":
		_, id, _, err := sessionFrom(args[1:], nil)
		if err != nil {
			return 2, err
		}
		return 0, runHolder(id)
	case "agent":
		return 0, runAgent(args[1:])
	case "pair":
		return 0, runPair(args[1:])
	case "version", "--version":
		if len(args) > 1 && args[1] == "--json" {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "protocol": protoVersion})
		} else {
			fmt.Println("age-plugin-yubikey-phone", version)
		}
		return 0, nil
	case "test":
		return 0, runTest(args[1:])
	case "devices":
		return 0, runDevices()
	case "ssh-opts":
		return 0, runSSHOpts(args[1:], os.Stdout)
	case "unpair":
		if len(args) != 2 {
			return 2, fmt.Errorf("usage: unpair NAME")
		}
		return 0, runUnpair(args[1])
	default:
		return 1, execRealPlugin(args)
	}
}

// runHold reads age's phase 1 and starts the session's phone request in the background (the race router's
// speculative start). A later --age-plugin=identity-v1 --session ID with the same phase 1 collects it.
func runHold(id string) (int, error) {
	p1, _, err := readPhase1(bufio.NewReader(os.Stdin))
	if err != nil {
		return 2, err
	}
	if len(p1.files) == 0 {
		return 1, fmt.Errorf("no piv-p256 stanza matches the identities given")
	}
	command, cwd := requester()
	resp, err := holderCall(id, &holderReq{Op: "hold", Digest: phase1Digest(p1.raw),
		Age: &ageQuery{Files: p1.files, Identities: p1.identities, Note: cleanNote(os.Getenv("KEYTAP_NOTE")), Command: command, Cwd: cwd}}, nil)
	if err != nil {
		return 1, err
	}
	if resp.Status != "ok" {
		return 1, fmt.Errorf("%s", resp.Message)
	}
	return 0, nil
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
