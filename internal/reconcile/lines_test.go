// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// A line without a record this pass keeps the status columns it has; a line with one
// takes the record's.
func TestWriteLinesKeepsTheRowOfALineWithoutARecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "supported-lines.csv")
	header := strings.Join(book.LineColumns, ",")
	err := os.WriteFile(path, []byte(header+"\n"+
		"a-1.x,maven,org.example:a-bom@1.0,,wave-1,a test,not fixed,v2026.09.15,2026-09-15T08:10:51Z,135,0,0,135,0,\n"+
		"c-1.x,maven,org.example:c-bom@1.0,,wave-1,a test,,,,,,,,,\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	err = WriteLines(path, []status.Record{{Line: "c-1.x", Status: "not fixed", BookVersion: "v2026.09.15.1", AsOf: "2026-09-15T09:00:00Z", InScope: 3, Open: []status.EntryRef{{}, {}, {}}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if lines[1] != "a-1.x,maven,org.example:a-bom@1.0,,wave-1,a test,not fixed,v2026.09.15,2026-09-15T08:10:51Z,135,0,0,135,0," {
		t.Fatalf("the skipped line lost its columns: %s", lines[1])
	}
	if lines[2] != "c-1.x,maven,org.example:c-bom@1.0,,wave-1,a test,not fixed,v2026.09.15.1,2026-09-15T09:00:00Z,3,0,0,3,0," {
		t.Fatalf("the record is not written: %s", lines[2])
	}
}
