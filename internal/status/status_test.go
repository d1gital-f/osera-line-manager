// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package status

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
)

const line = "spring-boot-2.7.x"

// tomcat-embed-core 9.0.83 carries 34 entries on the Wave 1 line; these five are among them.
const tomcat = "org.apache.tomcat.embed:tomcat-embed-core"

var tomcatCVEs = []string{"CVE-2025-24813", "CVE-2024-50379", "CVE-2024-56337", "CVE-2025-55754", "CVE-2025-31651"}

// the real Wave 1 backlog: 127 entries, 121 CVEs on the line
func realBook(t *testing.T) *book.Book {
	t.Helper()
	b, err := book.Read("testdata/cve-backlog.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func theLine(t *testing.T) book.Line {
	t.Helper()
	lines, err := book.ReadLines("testdata/supported-lines.csv")
	if err != nil {
		t.Fatal(err)
	}
	return lines[0]
}

func inputs(t *testing.T, promoted ...Promotion) Inputs {
	t.Helper()
	return Inputs{
		Line:              theLine(t),
		BookVersion:       "v2026.09.16",
		AsOf:              "2026-10-07T09:00:00Z",
		Book:              realBook(t),
		Promoted:          promoted,
		BacklogRepository: "backlog",
	}
}

// promotion is one patched coordinate in the release repository with its evidence.
func promotion(library, base, patch string, cves ...string) Promotion {
	group, artifact, _ := cut(library)
	ev := &releases.Evidence{Producer: "controlplane-dev", Release: base + releases.PatchSeparator + patch}
	for _, cve := range cves {
		ev.Fixes = append(ev.Fixes, releases.Fix{CVE: cve})
	}
	return Promotion{Coordinate: releases.NewCoordinate(group, artifact, base+releases.PatchSeparator+patch), Evidence: ev}
}

func cut(library string) (string, string, bool) {
	for i := 0; i < len(library); i++ {
		if library[i] == ':' {
			return library[:i], library[i+1:], true
		}
	}
	return library, "", false
}

// entry finds one entry of a record by CVE and library.
func entry(rec Record, cve, library string) book.Entry {
	for _, e := range rec.Entries {
		if e.CVE == cve && e.Library == library {
			return e
		}
	}
	return book.Entry{}
}

func mustCount(t *testing.T, rec Record, fixed, inProgress, open, notRemediable int) {
	t.Helper()
	if len(rec.Fixed) != fixed || len(rec.InProgress) != inProgress || len(rec.Open) != open || len(rec.NotRemediable) != notRemediable {
		t.Fatalf("fixed %d in progress %d open %d not remediable %d, want %d %d %d %d", len(rec.Fixed), len(rec.InProgress), len(rec.Open), len(rec.NotRemediable), fixed, inProgress, open, notRemediable)
	}
	if fixed+inProgress+open+notRemediable != rec.InScope {
		t.Fatalf("the counts add to %d, in scope is %d", fixed+inProgress+open+notRemediable, rec.InScope)
	}
}

// 1. Day one: nothing promoted, every entry open, the line is not fixed.
func TestDayOne(t *testing.T) {
	rec := Compute(inputs(t))
	if rec.InScope != 127 {
		t.Fatalf("in scope %d, want 127", rec.InScope)
	}
	mustCount(t, rec, 0, 0, 127, 0)
	if rec.Status != NotFixed {
		t.Fatalf("status %q, want %q", rec.Status, NotFixed)
	}
	if len(rec.Discrepancies) != 0 || len(rec.Entries) != 127 {
		t.Fatalf("discrepancies %v entries %d", rec.Discrepancies, len(rec.Entries))
	}
}

// 2. One promotion fixes three of the five tomcat entries named: three fixed, the
// rest open, the line in progress, the entries carry the coordinate and the time.
func TestOnePromotionFixesThreeOfFive(t *testing.T) {
	rec := Compute(inputs(t, promotion(tomcat, "9.0.83", "001", tomcatCVEs[0], tomcatCVEs[1], tomcatCVEs[2])))
	mustCount(t, rec, 3, 0, 124, 0)
	if rec.Status != InProgress {
		t.Fatalf("status %q, want %q", rec.Status, InProgress)
	}
	e := entry(rec, tomcatCVEs[0], tomcat)
	if e.Status != book.EntryFixed || e.FixedBy != tomcat+"@9.0.83+osera-patch.001" || e.FixedAt != "2026-10-07T09:00:00Z" {
		t.Fatalf("entry %+v", e)
	}
	if rec.Fixed[0].Patch != "001" {
		t.Fatalf("patch %q", rec.Fixed[0].Patch)
	}
	if entry(rec, tomcatCVEs[3], tomcat).Status != book.EntryOpen {
		t.Fatalf("the fourth CVE should stay open")
	}
}

// 3. A second patch of the same library replaces the first: the entries named by
// both are fixed by 002, the one only 001 named stays fixed by 001.
func TestSecondPatchReplacesTheFirst(t *testing.T) {
	rec := Compute(inputs(t,
		promotion(tomcat, "9.0.83", "001", tomcatCVEs[0], tomcatCVEs[1]),
		promotion(tomcat, "9.0.83", "002", tomcatCVEs[0], tomcatCVEs[2]),
	))
	mustCount(t, rec, 3, 0, 124, 0)
	if entry(rec, tomcatCVEs[0], tomcat).FixedBy != tomcat+"@9.0.83+osera-patch.002" {
		t.Fatalf("CVE named by both should be fixed by 002: %+v", entry(rec, tomcatCVEs[0], tomcat))
	}
	if entry(rec, tomcatCVEs[1], tomcat).FixedBy != tomcat+"@9.0.83+osera-patch.001" {
		t.Fatalf("CVE named by 001 only should stay fixed by 001")
	}
}

// 4. The file remembers a fix, the release repository no longer has the coordinate:
// the entry reopens, its fixed fields are cleared.
func TestCoordinateGoneReopens(t *testing.T) {
	in := inputs(t)
	for i := range in.Book.Entries {
		e := &in.Book.Entries[i]
		if e.CVE == tomcatCVEs[0] && e.Library == tomcat {
			e.Status = book.EntryFixed
			e.FixedBy = tomcat + "@9.0.83+osera-patch.001"
			e.FixedAt = "2026-09-30T10:00:00Z"
		}
	}
	rec := Compute(in)
	mustCount(t, rec, 0, 0, 127, 0)
	e := entry(rec, tomcatCVEs[0], tomcat)
	if e.Status != book.EntryOpen || e.FixedBy != "" || e.FixedAt != "" {
		t.Fatalf("entry %+v, want open with nothing fixed", e)
	}
	if rec.Status != NotFixed {
		t.Fatalf("status %q", rec.Status)
	}
}

// 5. The same coordinate again keeps the time the file remembers, so nothing churns.
func TestSameCoordinateKeepsTheTime(t *testing.T) {
	in := inputs(t, promotion(tomcat, "9.0.83", "001", tomcatCVEs[0]))
	for i := range in.Book.Entries {
		e := &in.Book.Entries[i]
		if e.CVE == tomcatCVEs[0] && e.Library == tomcat {
			e.Status = book.EntryFixed
			e.FixedBy = tomcat + "@9.0.83+osera-patch.001"
			e.FixedAt = "2026-09-30T10:00:00Z"
		}
	}
	rec := Compute(in)
	if entry(rec, tomcatCVEs[0], tomcat).FixedAt != "2026-09-30T10:00:00Z" {
		t.Fatalf("the time should be kept: %+v", entry(rec, tomcatCVEs[0], tomcat))
	}
}

// 6. Evidence naming a CVE the backlog has no entry for on that library is a
// discrepancy, and so is a coordinate on another base version, and one with no
// evidence at all. None of them fixes anything.
func TestPromotionDiscrepancies(t *testing.T) {
	noEvidence := Promotion{Coordinate: releases.NewCoordinate("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.83+osera-patch.003")}
	otherLine := promotion("org.example:not-on-this-line", "1.0", "001", "CVE-2099-0001")
	rec := Compute(inputs(t,
		promotion(tomcat, "9.0.83", "001", tomcatCVEs[0], "CVE-2099-0002"),
		promotion(tomcat, "9.0.80", "001", tomcatCVEs[1]),
		noEvidence,
		otherLine,
	))
	mustCount(t, rec, 1, 0, 126, 0)
	want := []string{
		"fixed, not in the backlog: CVE-2099-0002 on " + tomcat + "@9.0.83+osera-patch.001",
		"promoted " + tomcat + "@9.0.80+osera-patch.001 is on base 9.0.80, the line has " + tomcat + " at 9.0.83",
		"promoted " + tomcat + "@9.0.83+osera-patch.003 has no evidence file next to it, it fixes nothing",
	}
	if len(rec.Discrepancies) != len(want) {
		t.Fatalf("discrepancies %v", rec.Discrepancies)
	}
	for i := range want {
		if rec.Discrepancies[i] != want[i] {
			t.Fatalf("discrepancy %d: %q, want %q", i, rec.Discrepancies[i], want[i])
		}
	}
}

// 7. An issue moved into a patch repository is in progress, one in the backlog is
// not; the entry records the repository. Nothing fixed: the line is not fixed.
func TestInProgress(t *testing.T) {
	in := inputs(t)
	in.Issues = []Issue{
		{CVE: "CVE-2025-52999", Repository: "patch-jackson-core", Number: 7, State: "OPEN"},
		{CVE: "CVE-2024-38816", Repository: "backlog", Number: 8, State: "OPEN"},
	}
	rec := Compute(in)
	mustCount(t, rec, 0, 1, 126, 0)
	if rec.InProgress[0].CVE != "CVE-2025-52999" {
		t.Fatalf("in progress %v", rec.InProgress)
	}
	e := entry(rec, "CVE-2025-52999", "com.fasterxml.jackson.core:jackson-core")
	if e.Status != book.EntryInProgress || e.Repository != "patch-jackson-core" {
		t.Fatalf("entry %+v", e)
	}
	if rec.Status != NotFixed {
		t.Fatalf("status %q with nothing fixed, want %q", rec.Status, NotFixed)
	}
}

// 8. A closed issue on an entry that is not fixed is a discrepancy; the entry keeps its state.
func TestClosedIssueOnOpenEntry(t *testing.T) {
	in := inputs(t)
	in.Issues = []Issue{{CVE: "CVE-2025-52999", Repository: "patch-jackson-core", Number: 7, State: "CLOSED"}}
	rec := Compute(in)
	mustCount(t, rec, 0, 1, 126, 0)
	if len(rec.Discrepancies) != 1 || rec.Discrepancies[0] != "issue #7 for CVE-2025-52999 is closed in patch-jackson-core while the entry on com.fasterxml.jackson.core:jackson-core is in progress" {
		t.Fatalf("discrepancies %v", rec.Discrepancies)
	}
}

// 9. The "not remediable" label on the issue declares the entry, wherever the issue
// lives: counted apart, the reason on the issue. A fixed entry ignores the label.
func TestNotRemediableLabel(t *testing.T) {
	in := inputs(t, promotion(tomcat, "9.0.83", "001", tomcatCVEs[0]))
	in.Issues = []Issue{
		{CVE: "CVE-2016-1000027", Repository: "patch-spring-framework", Number: 1, State: "OPEN", NotRemediable: true},
		{CVE: tomcatCVEs[0], Repository: "patch-tomcat-embed-core", Number: 2, State: "CLOSED", NotRemediable: true},
	}
	rec := Compute(in)
	mustCount(t, rec, 1, 0, 125, 1)
	if rec.NotRemediable[0].CVE != "CVE-2016-1000027" || rec.NotRemediable[0].Reason != ReasonOnIssue {
		t.Fatalf("not remediable %+v", rec.NotRemediable)
	}
	if entry(rec, "CVE-2016-1000027", "org.springframework:spring-web").Status != book.EntryNotRemediable {
		t.Fatalf("entry %+v", entry(rec, "CVE-2016-1000027", "org.springframework:spring-web"))
	}
	if len(rec.Discrepancies) != 0 {
		t.Fatalf("a closed issue on a fixed entry is not a discrepancy: %v", rec.Discrepancies)
	}
}

// 10. The file says not remediable: kept while the board has no card for it, reopened
// when a card exists without the label, and the producer's reason survives the keep.
func TestNotRemediableFromTheFile(t *testing.T) {
	in := inputs(t)
	for i := range in.Book.Entries {
		e := &in.Book.Entries[i]
		if e.CVE == "CVE-2016-1000027" {
			e.Status = book.EntryNotRemediable
			e.Producer = "moderne"
			e.Reason = "upstream removed the remoting package in 6.0 and will not fix"
		}
	}
	rec := Compute(in)
	if len(rec.NotRemediable) != 1 || rec.NotRemediable[0].Producer != "moderne" || rec.NotRemediable[0].Reason != "upstream removed the remoting package in 6.0 and will not fix" {
		t.Fatalf("not remediable %+v", rec.NotRemediable)
	}
	in.Issues = []Issue{{CVE: "CVE-2016-1000027", Repository: "patch-spring-framework", Number: 1, State: "OPEN"}}
	rec = Compute(in)
	mustCount(t, rec, 0, 1, 126, 0)
	e := entry(rec, "CVE-2016-1000027", "org.springframework:spring-web")
	if e.Status != book.EntryInProgress || e.Reason != "" || e.Producer != "" {
		t.Fatalf("entry %+v, want in progress with the declaration cleared", e)
	}
}

// 11. Everything fixed or not remediable: the line is fixed, the counts add up.
func TestFixed(t *testing.T) {
	in := inputs(t)
	byLibrary := map[string][]string{}
	versions := map[string]string{}
	for _, e := range in.Book.ForLine(line) {
		if e.CVE == "CVE-2016-1000027" {
			continue
		}
		byLibrary[e.Library] = append(byLibrary[e.Library], e.CVE)
		versions[e.Library] = e.Version
	}
	for library, cves := range byLibrary {
		in.Promoted = append(in.Promoted, promotion(library, versions[library], "001", cves...))
	}
	in.Issues = []Issue{{CVE: "CVE-2016-1000027", Repository: "patch-spring-framework", Number: 1, State: "OPEN", NotRemediable: true}}
	in.Consume = "org.finos.osera:osera-bom-spring-boot-2.7.x@2026.12.01"
	rec := Compute(in)
	if rec.Status != Fixed {
		t.Fatalf("status %q, open %v in progress %v", rec.Status, rec.Open, rec.InProgress)
	}
	mustCount(t, rec, 126, 0, 0, 1)
	if rec.Consume != in.Consume || len(rec.Discrepancies) != 0 {
		t.Fatalf("consume %q discrepancies %v", rec.Consume, rec.Discrepancies)
	}
}

// 12. A fix for another line's library, and a coordinate that is not patched, count for nothing.
func TestUnrelatedPromotions(t *testing.T) {
	plain := Promotion{Coordinate: releases.NewCoordinate("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.83"), Evidence: &releases.Evidence{Fixes: []releases.Fix{{CVE: tomcatCVEs[0]}}}}
	rec := Compute(inputs(t, plain, promotion("org.example:lib", "1.0", "001", tomcatCVEs[0])))
	mustCount(t, rec, 0, 0, 127, 0)
	if len(rec.Discrepancies) != 0 {
		t.Fatalf("discrepancies %v", rec.Discrepancies)
	}
}

// 13. The lists and the entries come out in a stable order.
func TestStableOrder(t *testing.T) {
	rec := Compute(inputs(t, promotion(tomcat, "9.0.83", "001", tomcatCVEs[1], tomcatCVEs[0])))
	if rec.Fixed[0].CVE != "CVE-2024-50379" || rec.Fixed[1].CVE != "CVE-2025-24813" {
		t.Fatalf("fixed order %v", rec.Fixed)
	}
	for i := 1; i < len(rec.Entries); i++ {
		if !entryLess(rec.Entries[i-1].CVE, rec.Entries[i-1].Library, rec.Entries[i].CVE, rec.Entries[i].Library) {
			t.Fatalf("entries out of order at %d", i)
		}
	}
}
