// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// The words of the log: what changed, named, and why it matters.
func TestWords(t *testing.T) {
	// 1. the board with the claimed cards named
	issues := []status.Issue{
		{CVE: "CVE-1", Repository: "backlog", Number: 4, State: "OPEN"},
		{CVE: "CVE-2", Repository: "patch-jackson-core", Number: 1, State: "OPEN"},
		{CVE: "CVE-3", Repository: "patch-jackson-core", Number: 2, State: "CLOSED"},
		{CVE: "CVE-4", Repository: "patch-snakeyaml", Number: 1, State: "OPEN", NotRemediable: true},
	}
	got := boardWords(issues, "backlog")
	want := "board: 4 cards; 3 claimed by a producer (moved to a patch repository): #1 #2 in patch-jackson-core, #1 in patch-snakeyaml; 1 closed; 1 marked not remediable"
	if got != want {
		t.Fatalf("board:\n%s\n%s", got, want)
	}

	// 2. the transitions of a line, grouped by the move, the fix named
	before := map[string]string{
		entryKey("dev", "CVE-1", "g:a"): book.EntryInProgress,
		entryKey("dev", "CVE-2", "g:a"): book.EntryInProgress,
		entryKey("dev", "CVE-3", "g:b"): book.EntryOpen,
		entryKey("dev", "CVE-4", "g:c"): book.EntryOpen,
	}
	entries := []book.Entry{
		{CVE: "CVE-1", Library: "g:a", Status: book.EntryFixed, FixedBy: "g:a@1+osera-patch.001"},
		{CVE: "CVE-2", Library: "g:a", Status: book.EntryFixed, FixedBy: "g:a@1+osera-patch.001"},
		{CVE: "CVE-3", Library: "g:b", Status: book.EntryInProgress},
		{CVE: "CVE-4", Library: "g:c", Status: book.EntryOpen},
	}
	lines := transitions("dev", before, entries)
	if len(lines) != 2 || lines[0] != "2 entries went from in progress to fixed by g:a@1+osera-patch.001: CVE-1 in a, CVE-2 in a" || lines[1] != "1 entry went from open to in progress: CVE-3 in b" {
		t.Fatalf("transitions %q", lines)
	}

	// 3. the changes to commit, in words
	got = changesWords([]string{"cve-backlog.json", "graphs/dev/maven.cdx.json", "status/dev.json", "status/spring.json", "supported-lines.csv"})
	if got != "cve-backlog.json, supported-lines.csv, 1 graph file(s), 2 status file(s)" {
		t.Fatalf("changes %q", got)
	}

	// 4. the line at the end of the pass
	rec := status.Record{Line: "dev-1.0.x", Status: "fixed", InScope: 3, Fixed: []status.FixedEntry{{}, {}, {}}, Consume: "org.finos.osera:osera-bom-dev-1.0.x@2026.09.15"}
	if recordWords(rec) != "dev-1.0.x: fixed. 3 in scope: 3 fixed, 0 in progress, 0 open, 0 not remediable. Banks consume org.finos.osera:osera-bom-dev-1.0.x@2026.09.15." {
		t.Fatalf("record %q", recordWords(rec))
	}
	old := status.Record{Line: "dev-1.0.x", Status: "not fixed", InScope: 3, Open: []status.EntryRef{{}, {}, {}}}
	if recordWordsWas(rec, old) != "dev-1.0.x: fixed (was not fixed). 3 in scope: 3 fixed (was 0), 0 in progress, 0 open (was 3), 0 not remediable. Banks consume org.finos.osera:osera-bom-dev-1.0.x@2026.09.15." {
		t.Fatalf("record was %q", recordWordsWas(rec, old))
	}

	// 5. a scan compared with the backlog
	if scanDelta(entries, entries) != "compared with the backlog: nothing new, 4 entries unchanged" {
		t.Fatalf("delta %q", scanDelta(entries, entries))
	}
	more := append([]book.Entry{}, entries...)
	more = append(more, book.Entry{CVE: "CVE-9", Library: "g:z", Priority: "P1"})
	if scanDelta(entries, more) != "compared with the backlog: 1 new (CVE-9 in z)" {
		t.Fatalf("delta %q", scanDelta(entries, more))
	}

	// 6. the release repository
	got = releasesWords(7, 3, 2, []string{"g:a@1+osera-patch.001"}, []string{"g:b@2+osera-patch.001"})
	if got != "release repository: 7 coordinates, 3 patched jars, 2 with an evidence file; 1 new since the last pass: g:a@1+osera-patch.001; 1 without an evidence file yet (g:b@2+osera-patch.001), they fix nothing until it appears" {
		t.Fatalf("releases %q", got)
	}
}
