package main

// The age plugin wire format (C2SP age-plugin spec): a stanza is a line "-> tag arg arg…"
// followed by its body as unpadded standard base64, wrapped at 64 columns, terminated by a
// line shorter than 64 characters (an empty line when the body length is a multiple of 48).

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

var b64 = base64.RawStdEncoding

type Stanza struct {
	Tag  string
	Args []string
	Body []byte
}

func readStanza(r *bufio.Reader) (*Stanza, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\n")
	if !strings.HasPrefix(line, "-> ") {
		return nil, fmt.Errorf("malformed stanza line %q", line)
	}
	f := strings.Fields(strings.TrimPrefix(line, "-> "))
	if len(f) == 0 {
		return nil, errors.New("empty stanza tag")
	}
	s := &Stanza{Tag: f[0], Args: f[1:]}
	var enc strings.Builder
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		l = strings.TrimSuffix(l, "\n")
		if len(l) > 64 {
			return nil, errors.New("stanza body line too long")
		}
		enc.WriteString(l)
		if len(l) < 64 {
			break
		}
	}
	s.Body, err = b64.DecodeString(enc.String())
	if err != nil {
		return nil, fmt.Errorf("stanza body: %w", err)
	}
	return s, nil
}

func writeStanza(w io.Writer, tag string, args []string, body []byte) error {
	var b strings.Builder
	b.WriteString("-> ")
	b.WriteString(tag)
	for _, a := range args {
		b.WriteString(" ")
		b.WriteString(a)
	}
	b.WriteString("\n")
	enc := b64.EncodeToString(body)
	for len(enc) >= 64 {
		b.WriteString(enc[:64])
		b.WriteString("\n")
		enc = enc[64:]
	}
	b.WriteString(enc)
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}
