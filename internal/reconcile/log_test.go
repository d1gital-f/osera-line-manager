// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Every line starts with the full timestamp in RFC 3339 UTC; the level filters:
// a high line is not printed at medium, a low line is printed at every level.
func TestLogLevelsAndStamp(t *testing.T) {
	// 1. a fixed clock and a buffer
	var buf bytes.Buffer
	logMu.Lock()
	oldOut, oldClock, oldLevel := logOut, logClock, logLevel
	logOut = &buf
	logClock = func() time.Time { return time.Date(2026, 9, 14, 19, 6, 29, 0, time.FixedZone("CEST", 2*3600)) }
	logMu.Unlock()
	defer func() {
		logMu.Lock()
		logOut, logClock, logLevel = oldOut, oldClock, oldLevel
		logMu.Unlock()
	}()

	// 2. at medium: low and medium print, high does not
	SetLevel(Medium)
	Lowf("a write")
	logf("a step")
	highf("a detail")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("at medium %d lines, want 2: %q", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "2026-09-14T17:06:29Z a write") {
		t.Fatalf("stamp or text wrong: %q", lines[0])
	}

	// 3. at low: only the low line
	buf.Reset()
	SetLevel(Low)
	Lowf("a write")
	logf("a step")
	highf("a detail")
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("at low: %q", buf.String())
	}

	// 4. at high: all three
	buf.Reset()
	SetLevel(High)
	Lowf("a write")
	logf("a step")
	highf("a detail")
	if strings.Count(buf.String(), "\n") != 3 {
		t.Fatalf("at high: %q", buf.String())
	}

	// 5. the words
	for _, in := range []string{"low", "Medium", "HIGH", ""} {
		if _, err := ParseLevel(in); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Fatal("loud accepted")
	}
}
