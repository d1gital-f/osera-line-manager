// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package intent is the write ahead note the line manager leaves before it
// writes anywhere outside itself: a commit on GitHub, a BOM in the release
// repository. When the write comes back to it as an event or a fetch, the note
// says it was its own. A crash between the write and the note's clearing is
// recovered the same way.
package intent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Intent is what the line manager was about to do.
type Intent struct {
	// Kind is commit, tag, bom or issue.
	Kind string `json:"kind"`
	// Line is the line the write is about.
	Line string `json:"line"`
	// Ref names the thing written: a commit sha, a tag, a BOM coordinate, an issue number.
	Ref string `json:"ref"`
	// At is when the note was written, RFC 3339 UTC.
	At time.Time `json:"at"`
}

// Write writes the note, whole or not at all.
func Write(path string, in Intent) error {
	// 1. the bytes
	if in.At.IsZero() {
		in.At = time.Now().UTC()
	}
	raw, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}

	// 2. a temporary file, then the rename, so a crash leaves the old note or the new, never half
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing the intent: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("writing the intent: %w", err)
	}
	return nil
}

// Read reads the note. A missing file is os.ErrNotExist, the caller decides.
func Read(path string) (*Intent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in Intent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("reading the intent: %w", err)
	}
	return &in, nil
}

// Clear removes the note. Nothing to remove is fine.
func Clear(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
