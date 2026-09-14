// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 1. Written, read back the same, cleared, gone.
func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intent.json")
	if _, err := Read(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing note read as %v", err)
	}
	at := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	in := Intent{Kind: "bom", Line: "spring-boot-2.7.x", Ref: "org.finos.osera:osera-bom-spring-boot-2.7.x@2026.10.07", At: at}
	if err := Write(path, in); err != nil {
		t.Fatal(err)
	}
	back, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if *back != in {
		t.Fatalf("read %+v, wrote %+v", *back, in)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary file was left behind")
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if err := Clear(path); err != nil {
		t.Fatalf("clearing twice: %v", err)
	}
	if _, err := Read(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a cleared note read as %v", err)
	}
}

// 2. A note without a time gets one.
func TestWriteStampsTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intent.json")
	if err := Write(path, Intent{Kind: "commit", Line: "dev-1.0.x", Ref: "abc"}); err != nil {
		t.Fatal(err)
	}
	back, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.At.IsZero() {
		t.Fatal("no time stamped")
	}
}
