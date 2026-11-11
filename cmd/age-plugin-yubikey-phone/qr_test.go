package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func qrDigest(m [][]bool) string {
	h := sha256.New()
	for _, row := range m {
		for _, d := range row {
			if d {
				h.Write([]byte{1})
			} else {
				h.Write([]byte{0})
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The golden digests are of codes that Apple's QR detector (CIDetector) read back as the same text.
func TestQREncode(t *testing.T) {
	link := "keytap://pair?code=AAAAAAAAAAAAAAAAAAAAAA&fp=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&host=192.0.2.10%3A8743&name=workstation&v=1"
	for _, c := range []struct {
		text   string
		size   int
		digest string
	}{
		{"a", 21, "e0eaa9451b23803acd598cdcd8d99adde8caa43b11da279e22533be2510d2a6d"},
		{link, 41, "5335e487b3e3c14e7126201692e205b5451de308926ef68e1c1c598ee84e2c22"},
		{strings.Repeat("g", 850), 97, "5d06367bf1a5b37e5d4296c4bdd7d38ff0194e438b107fc01ca96ca6ab3c365a"},
	} {
		m, err := qrEncode(c.text)
		if err != nil {
			t.Fatal(err)
		}
		if len(m) != c.size {
			t.Errorf("%d bytes: size %d, want %d", len(c.text), len(m), c.size)
		}
		if got := qrDigest(m); got != c.digest {
			t.Errorf("%d bytes: digest %s, want %s", len(c.text), got, c.digest)
		}
	}
	if _, err := qrEncode(strings.Repeat("h", 859)); err == nil {
		t.Error("859 bytes fit no version up to 20, but no error")
	}
}

func TestPrintQR(t *testing.T) {
	var b bytes.Buffer
	if err := printQR(&b, "keytap://pair?v=1", "  "); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	// version 1 or 2 plus a quiet zone of 4 on every side, two module rows per line
	if n := len(lines); n != (25+8+1)/2 && n != (21+8+1)/2 {
		t.Errorf("%d lines", n)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "  \x1b[30;107m") || !strings.HasSuffix(l, "\x1b[0m") {
			t.Fatalf("line not black on white: %q", l)
		}
	}
}
