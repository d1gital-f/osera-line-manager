// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// xmlUnmarshal reads a POM; kept apart so the resolve file does not import xml.
// Old POMs on Central declare iso-8859-1, which Go's decoder refuses unless told
// how to read it, so the decoder gets a charset reader for the encodings a POM
// can plausibly carry. Anything else is an error, named.
func xmlUnmarshal(raw []byte, into *pom) error {
	// 1. a decoder that knows the single byte encodings
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.CharsetReader = charsetReader

	// 2. the read
	return d.Decode(into)
}

// charsetReader turns a declared encoding into a reader that yields UTF-8.
func charsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "windows-1252", "cp1252":
		return latin1Reader{r: input}, nil
	}
	return nil, fmt.Errorf("POM declares encoding %q, not supported", label)
}

// latin1Reader maps every byte to the rune of the same value, which is exactly
// what ISO 8859-1 is; windows-1252 differs only in the 0x80 to 0x9F range,
// which a POM never uses for anything that matters to a resolve.
type latin1Reader struct {
	r   io.Reader
	buf []byte
}

func (l latin1Reader) Read(p []byte) (int, error) {
	// 1. read up to half the space, every byte can become two
	raw := make([]byte, len(p)/2+1)
	n, err := l.r.Read(raw)
	if n == 0 {
		return 0, err
	}

	// 2. bytes to runes to UTF-8
	out := make([]byte, 0, n*2)
	for _, b := range raw[:n] {
		out = append(out, string(rune(b))...)
	}
	copied := copy(p, out)
	return copied, err
}
