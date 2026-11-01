package main

// The computer's YubiKeys. The phone stores none of this: every request carries the list (serial +
// label) and the key to preselect, so adding or dropping a key is a change on the computer only.
//
//   $KEYTAP_KEYS (default ~/.secure/keytap/keys.conf), one key per line:
//       <serial> <label> [ssh <path to the .pub of a FIDO2 key on it>]...
//       12345678 everyday ssh ~/.ssh/id_ed25519_sk_everyday.pub
//   $KEYTAP_IDENTITIES (default ~/.secure/age/yubikeys.agekey): the age-plugin-yubikey identity file. Its
//       comments (Serial, Slot, Name, Recipient) are the fallback labels and the recipients `test` uses.
//   ~/.secure/keytap/last-key: the serial of the key last used successfully here (public; preselected).

import (
	"bufio"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type keyEntry struct {
	Serial    uint32
	Label     string
	Slot      uint8
	Recipient []byte   // 33-byte compressed P-256 point (from the identity file's comment), if known
	SSH       []string // .pub files of FIDO2 keys on this YubiKey
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

func keysConfPath() string {
	if p := os.Getenv("KEYTAP_KEYS"); p != "" {
		return expandHome(p)
	}
	return filepath.Join(stateDir(), "keys.conf")
}

func identityFilePath() string {
	if p := os.Getenv("KEYTAP_IDENTITIES"); p != "" {
		return expandHome(p)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secure", "age", "yubikeys.agekey")
}

// readKeysConf parses keys.conf; a missing file is an empty list.
func readKeysConf(path string) []keyEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []keyEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		serial, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || serial == 0 {
			continue
		}
		k := keyEntry{Serial: uint32(serial), Label: truncateRunes(fields[1], 40)}
		for i := 2; i+1 < len(fields); i += 2 {
			if fields[i] == "ssh" {
				k.SSH = append(k.SSH, expandHome(fields[i+1]))
			}
		}
		out = append(out, k)
	}
	return out
}

var (
	reSerial    = regexp.MustCompile(`Serial:\s*(\d+)(?:,\s*Slot:\s*(\d+))?`)
	reName      = regexp.MustCompile(`Name:\s*(.+)$`)
	reRecipient = regexp.MustCompile(`Recipient:\s*(age1yubikey1[0-9a-z]+)`)
)

// readIdentityFile parses an age-plugin-yubikey identity file: each AGE-PLUGIN-YUBIKEY-1… line, with the
// comments above it. The identity itself is authoritative for serial and slot.
func readIdentityFile(path string) []keyEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []keyEntry
	var cur keyEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "#"):
			if m := reSerial.FindStringSubmatch(line); m != nil {
				cur = keyEntry{}
			}
			if m := reName.FindStringSubmatch(line); m != nil {
				cur.Label = truncateRunes(strings.TrimSpace(m[1]), 40)
			}
			if m := reRecipient.FindStringSubmatch(line); m != nil {
				if hrp, data, err := bech32Decode(m[1]); err == nil && hrp == "age1yubikey" && len(data) == 33 {
					cur.Recipient = data
				}
			}
		case strings.HasPrefix(strings.ToUpper(line), "AGE-PLUGIN-YUBIKEY-"):
			if id, ok := parseIdentity(strings.ToLower(line)); ok {
				cur.Serial, cur.Slot = id.Serial, id.Slot
				out = append(out, cur)
			}
			cur = keyEntry{}
		}
	}
	return out
}

// knownKeys merges keys.conf (labels, ssh keys) with the identity file (slots, recipients, fallback labels).
func knownKeys() []keyEntry {
	conf := readKeysConf(keysConfPath())
	ids := readIdentityFile(identityFilePath())
	byID := map[uint32]keyEntry{}
	for _, k := range ids {
		byID[k.Serial] = k
	}
	var out []keyEntry
	seen := map[uint32]bool{}
	for _, k := range conf {
		if id, ok := byID[k.Serial]; ok {
			k.Slot, k.Recipient = id.Slot, id.Recipient
		}
		out = append(out, k)
		seen[k.Serial] = true
	}
	for _, k := range ids {
		if !seen[k.Serial] {
			out = append(out, k)
			seen[k.Serial] = true
		}
	}
	return out
}

func keyLabel(keys []keyEntry, serial uint32) string {
	for _, k := range keys {
		if k.Serial == serial && k.Label != "" {
			return k.Label
		}
	}
	return "YubiKey " + strconv.FormatUint(uint64(serial), 10)
}

// keyInfos is the request's key list: the given serials (in order) with their labels.
func keyInfos(keys []keyEntry, serials []uint32) []KeyInfo {
	var out []KeyInfo
	seen := map[uint32]bool{}
	for _, s := range serials {
		if s == 0 || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, KeyInfo{Serial: s, Label: keyLabel(keys, s)})
	}
	return out
}

func lastKeyPath() string { return filepath.Join(stateDir(), "last-key") }

func lastKey() uint32 {
	b, err := os.ReadFile(lastKeyPath())
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	return uint32(n)
}

func setLastKey(serial uint32) {
	if serial == 0 {
		return
	}
	os.MkdirAll(stateDir(), 0o700)
	tmp := lastKeyPath() + ".tmp"
	if os.WriteFile(tmp, []byte(strconv.FormatUint(uint64(serial), 10)+"\n"), 0o600) == nil {
		os.Rename(tmp, lastKeyPath())
	}
}

// pickDefault: the last key used here if the request offers it, else the first offered.
func pickDefault(infos []KeyInfo, fallback uint32) uint32 {
	last := lastKey()
	for _, k := range infos {
		if k.Serial == last {
			return last
		}
	}
	if fallback != 0 {
		return fallback
	}
	if len(infos) > 0 {
		return infos[0].Serial
	}
	return 0
}

// sshKeySerial: which YubiKey holds the sk key with this public blob, from keys.conf's ssh entries.
func sshKeySerial(keys []keyEntry, blob []byte) uint32 {
	want := base64.StdEncoding.EncodeToString(blob)
	for _, k := range keys {
		for _, p := range k.SSH {
			b, err := os.ReadFile(p)
			if err != nil || len(b) > 8192 {
				continue
			}
			if f := strings.Fields(string(b)); len(f) >= 2 && f[1] == want {
				return k.Serial
			}
		}
	}
	return 0
}
