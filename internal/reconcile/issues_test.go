// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Two issues numbered 1 in two patch repositories are two issues: both close when
// their entries turn fixed (15 Sept, patch-snakeyaml #1 closed and patch-jackson-core
// #1 skipped). An issue still open for an entry fixed on an earlier pass closes too.
func TestIssueActionsAreKeyedByRepositoryAndNumber(t *testing.T) {
	p := &pass{asOf: "2026-09-15T10:50:31Z", before: map[string]string{
		entryKey("dev-1.0.x", "CVE-2022-1471", "org.yaml:snakeyaml"):                       book.EntryInProgress,
		entryKey("dev-1.0.x", "CVE-2025-52999", "com.fasterxml.jackson.core:jackson-core"): book.EntryInProgress,
		entryKey("dev-1.0.x", "CVE-2024-0001", "org.example:lib"):                          book.EntryFixed,
	}}
	p.records = []status.Record{{Line: "dev-1.0.x", Consume: "org.finos.osera:osera-bom-dev-1.0.x@2026.09.15", Entries: []book.Entry{
		{CVE: "CVE-2022-1471", Library: "org.yaml:snakeyaml", Status: book.EntryFixed, FixedBy: "org.yaml:snakeyaml@1.33+osera-patch.001"},
		{CVE: "CVE-2025-52999", Library: "com.fasterxml.jackson.core:jackson-core", Status: book.EntryFixed, FixedBy: "com.fasterxml.jackson.core:jackson-core@2.14.2+osera-patch.001"},
		{CVE: "CVE-2024-0001", Library: "org.example:lib", Status: book.EntryFixed, FixedBy: "org.example:lib@1.0+osera-patch.001"},
		{CVE: "CVE-2024-0002", Library: "org.example:other", Status: book.EntryOpen},
	}}}
	issues := []status.Issue{
		{CVE: "CVE-2022-1471", Repository: "patch-snakeyaml", Number: 1, State: "OPEN"},
		{CVE: "CVE-2025-52999", Repository: "patch-jackson-core", Number: 1, State: "OPEN"},
		{CVE: "CVE-2024-0001", Repository: "patch-lib", Number: 7, State: "OPEN"},
		{CVE: "CVE-2024-0002", Repository: "backlog", Number: 9, State: "OPEN"},
	}
	actions := issueActions(p, issues)
	if len(actions) != 3 {
		t.Fatalf("actions %+v", actions)
	}
	if actions[0].Repository != "patch-snakeyaml" || actions[0].Number != 1 || actions[1].Repository != "patch-jackson-core" || actions[1].Number != 1 {
		t.Fatalf("both number 1 issues must close: %+v", actions)
	}
	if actions[2].Repository != "patch-lib" || actions[2].Reopen {
		t.Fatalf("the issue left open for an entry fixed earlier must close: %+v", actions)
	}
	if actions[1].Comment != "Fixed by com.fasterxml.jackson.core:jackson-core@2.14.2+osera-patch.001, in osera-bom-dev-1.0.x 2026.09.15." {
		t.Fatalf("comment %q", actions[1].Comment)
	}
}

// The cards to move: the open issue of an in progress entry, in a patch repository,
// not yet in the In Progress lane, letter case aside; each card once.
func TestLaneMoves(t *testing.T) {
	records := []status.Record{{Line: "dev-1.0.x", Entries: []book.Entry{
		{CVE: "CVE-1", Library: "a", Status: book.EntryInProgress},
		{CVE: "CVE-2", Library: "b", Status: book.EntryInProgress},
		{CVE: "CVE-3", Library: "c", Status: book.EntryInProgress},
		{CVE: "CVE-4", Library: "d", Status: book.EntryOpen},
		{CVE: "CVE-5", Library: "e", Status: book.EntryInProgress},
	}}, {Line: "spring-boot-2.7.x", Entries: []book.Entry{
		{CVE: "CVE-1", Library: "a", Status: book.EntryInProgress},
	}}}
	issues := []status.Issue{
		{CVE: "CVE-1", Repository: "patch-a", Number: 1, State: "OPEN", ItemID: "i1", Lane: "Not claimed"},
		{CVE: "CVE-2", Repository: "patch-b", Number: 1, State: "OPEN", ItemID: "i2", Lane: "in progress"},
		{CVE: "CVE-3", Repository: "patch-c", Number: 2, State: "CLOSED", ItemID: "i3", Lane: "Not claimed"},
		{CVE: "CVE-4", Repository: "backlog", Number: 4, State: "OPEN", ItemID: "i4", Lane: "Not claimed"},
		{CVE: "CVE-5", Repository: "patch-e", Number: 5, State: "OPEN", ItemID: "", Lane: ""},
		{CVE: "CVE-6", Repository: "somewhere-else", Number: 6, State: "OPEN", ItemID: "i6", Lane: "Not claimed"},
	}
	records[0].Entries = append(records[0].Entries, book.Entry{CVE: "CVE-6", Library: "g:f", Status: book.EntryInProgress})
	moves := laneMoves(records, issues, "backlog")
	if len(moves) != 1 || moves[0].ItemID != "i1" || moves[0].CVE != "CVE-1 in a" {
		t.Fatalf("moves %+v", moves)
	}
}

// A scan record carries a digest of the rules and the advisory file: when either changes
// the line is due again, whatever the interval; unchanged, the interval decides.
func TestScanDecisionOnChangedInputs(t *testing.T) {
	dir := t.TempDir()
	r := &Reconciler{cfg: Config{RescanInterval: 168 * time.Hour, DevAdvisories: "advisories/dev.json"}, now: time.Now}
	r.cfg.CloneDir = dir
	r.cfg.CacheDir = filepath.Join(dir, "cache")
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.cfg.CacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "prioritisation.yaml"), []byte("version: 0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &pass{staged: map[string][]byte{}, book: &book.Book{Entries: []book.Entry{{CVE: "CVE-1", Library: "g:a", Lines: []string{"dev"}}}}}
	ln := book.Line{ID: "dev"}

	// 1. scanned now with the current inputs: not due
	p.scanned = []string{"dev"}
	if err := r.writeStamps(p); err != nil {
		t.Fatal(err)
	}
	due, why := r.scanDecision(p, ln)
	if due {
		t.Fatalf("just scanned, yet due: %s", why)
	}

	// 2. the rules file changes: due, and the reason says so
	if err := os.WriteFile(filepath.Join(dir, "rules", "prioritisation.yaml"), []byte("version: 0.2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	due, why = r.scanDecision(p, ln)
	if !due || !strings.Contains(why, "rules file or the advisory file changed") {
		t.Fatalf("a changed rules file must make the line due: %v %s", due, why)
	}
}
