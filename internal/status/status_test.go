// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package status

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/ledger"
)

const line = "spring-framework-5.3.x"

// the real Wave 1 book, 121 CVEs on the line
func realBook(t *testing.T) *book.Book {
	b, err := book.Read("testdata/cve-backlog.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func inputs(t *testing.T, l *ledger.Ledger) Inputs {
	return Inputs{
		Line:              line,
		BookVersion:       "v2026.09.09",
		AsOf:              "2026-09-09T14:00:00Z",
		Book:              realBook(t),
		Ledger:            l,
		BacklogRepository: "backlog",
	}
}

func promoted(setID string, cves ...string) ledger.Event {
	return ledger.Event{Type: "promoted", Line: line, SetID: setID, Coordinates: []string{"org.example:lib@1.0+osera-patch.001"}, CVEs: cves, At: "2026-09-20T10:00:00Z"}
}

// 1. Day one: nothing promoted, every CVE open, the line is partially remediated.
func TestEmptyLedger(t *testing.T) {
	rec := Compute(inputs(t, ledger.Empty()))
	if rec.InScope != 121 {
		t.Fatalf("in scope %d, want 121", rec.InScope)
	}
	if len(rec.Open) != 121 || len(rec.Fixed) != 0 {
		t.Fatalf("open %d fixed %d, want 121 and 0", len(rec.Open), len(rec.Fixed))
	}
	if rec.Status != PartiallyRemediated {
		t.Fatalf("status %q", rec.Status)
	}
}

// 2. One release set fixes two CVEs: two fixed, the rest open.
func TestOnePromotion(t *testing.T) {
	l := &ledger.Ledger{Events: []ledger.Event{promoted("set-1", "CVE-2024-38816", "CVE-2024-38819")}}
	rec := Compute(inputs(t, l))
	if len(rec.Fixed) != 2 || len(rec.Open) != 119 {
		t.Fatalf("fixed %d open %d, want 2 and 119", len(rec.Fixed), len(rec.Open))
	}
	if rec.Fixed[0].SetID != "set-1" {
		t.Fatalf("set id %q", rec.Fixed[0].SetID)
	}
}

// 3. A retraction of the set puts its CVEs back to open.
func TestRetraction(t *testing.T) {
	l := &ledger.Ledger{Events: []ledger.Event{
		promoted("set-1", "CVE-2024-38816", "CVE-2024-38819"),
		{Type: "retracted", Line: line, SetID: "set-1", At: "2026-09-21T10:00:00Z"},
	}}
	rec := Compute(inputs(t, l))
	if len(rec.Fixed) != 0 || len(rec.Open) != 121 {
		t.Fatalf("fixed %d open %d after retraction, want 0 and 121", len(rec.Fixed), len(rec.Open))
	}
}

// 4. A retraction of one set does not unfix a CVE a later set fixed again.
func TestRetractionKeepsLaterFix(t *testing.T) {
	l := &ledger.Ledger{Events: []ledger.Event{
		promoted("set-1", "CVE-2024-38816"),
		promoted("set-2", "CVE-2024-38816"),
		{Type: "retracted", Line: line, SetID: "set-1", At: "2026-09-21T10:00:00Z"},
	}}
	rec := Compute(inputs(t, l))
	if len(rec.Fixed) != 1 || rec.Fixed[0].SetID != "set-2" {
		t.Fatalf("fixed %+v, want CVE-2024-38816 by set-2", rec.Fixed)
	}
}

// 5. A CVE declared not remediable is counted apart and leaves open.
func TestNotRemediable(t *testing.T) {
	l := &ledger.Ledger{Events: []ledger.Event{
		{Type: "not-remediable", Line: line, CVE: "CVE-2016-1000027", Reason: "upstream removed the remoting package in 6.0 and will not fix", Producer: "moderne", At: "2026-09-20T10:00:00Z"},
	}}
	rec := Compute(inputs(t, l))
	if len(rec.NotRemediable) != 1 || len(rec.Open) != 120 {
		t.Fatalf("not remediable %d open %d, want 1 and 120", len(rec.NotRemediable), len(rec.Open))
	}
}

// 6. An issue moved into a patch repository is in progress, one in backlog is not.
func TestInProgress(t *testing.T) {
	in := inputs(t, ledger.Empty())
	in.Issues = []Issue{
		{CVE: "CVE-2025-52999", Repository: "patch-jackson-core"},
		{CVE: "CVE-2024-38816", Repository: "backlog"},
	}
	rec := Compute(in)
	if len(rec.InProgress) != 1 || rec.InProgress[0] != "CVE-2025-52999" {
		t.Fatalf("in progress %v", rec.InProgress)
	}
	if len(rec.Open) != 120 {
		t.Fatalf("open %d, want 120", len(rec.Open))
	}
}

// 7. Everything fixed or declared, nothing new: remediated.
func TestRemediated(t *testing.T) {
	b := realBook(t)
	var cves []string
	seen := map[string]bool{}
	for _, e := range b.ForLine(line) {
		if e.CVE == "CVE-2016-1000027" || seen[e.CVE] {
			continue
		}
		seen[e.CVE] = true
		cves = append(cves, e.CVE)
	}
	l := &ledger.Ledger{Events: []ledger.Event{
		promoted("set-all", cves...),
		{Type: "not-remediable", Line: line, CVE: "CVE-2016-1000027", Reason: "upstream will not fix", Producer: "moderne", At: "2026-09-20T10:00:00Z"},
	}}
	rec := Compute(inputs(t, l))
	if rec.Status != Remediated {
		t.Fatalf("status %q, open %v in progress %v", rec.Status, rec.Open, rec.InProgress)
	}
	if len(rec.Fixed) != 120 || len(rec.NotRemediable) != 1 {
		t.Fatalf("fixed %d not remediable %d", len(rec.Fixed), len(rec.NotRemediable))
	}
}

// 8. A new advisory the book does not carry makes a remediated line partial again.
func TestNewAdvisory(t *testing.T) {
	b := realBook(t)
	var cves []string
	seen := map[string]bool{}
	for _, e := range b.ForLine(line) {
		if !seen[e.CVE] {
			seen[e.CVE] = true
			cves = append(cves, e.CVE)
		}
	}
	in := inputs(t, &ledger.Ledger{Events: []ledger.Event{promoted("set-all", cves...)}})
	in.Advisories = []Advisory{
		{CVE: "CVE-2026-99999", Library: "org.springframework:spring-core", Version: "5.3.39", Severity: 9.1},
		{CVE: "CVE-2026-99998", Library: "org.springframework:spring-core", Version: "5.3.39", Severity: 5.4},
	}
	rec := Compute(in)
	if rec.Status != PartiallyRemediated || len(rec.NewSinceBook) != 1 || rec.NewSinceBook[0].CVE != "CVE-2026-99999" {
		t.Fatalf("status %q new %v", rec.Status, rec.NewSinceBook)
	}
	if len(rec.OutsideBook) != 1 || rec.OutsideBook[0].CVE != "CVE-2026-99998" {
		t.Fatalf("outside %v", rec.OutsideBook)
	}
}

// 10. A CVE below the bar outside the book is tracked and leaves a remediated line remediated.
func TestBelowBarDoesNotCount(t *testing.T) {
	b := realBook(t)
	var cves []string
	seen := map[string]bool{}
	for _, e := range b.ForLine(line) {
		if !seen[e.CVE] {
			seen[e.CVE] = true
			cves = append(cves, e.CVE)
		}
	}
	in := inputs(t, &ledger.Ledger{Events: []ledger.Event{promoted("set-all", cves...)}})
	in.Advisories = []Advisory{{CVE: "CVE-2026-99998", Library: "org.springframework:spring-core", Version: "5.3.39", Severity: 5.4}}
	rec := Compute(in)
	if rec.Status != Remediated || len(rec.OutsideBook) != 1 || len(rec.NewSinceBook) != 0 {
		t.Fatalf("status %q outside %v new %v", rec.Status, rec.OutsideBook, rec.NewSinceBook)
	}
}

// 9. A fix recorded for another line, or for a CVE outside the book, does not count.
func TestOtherLineAndOutOfScope(t *testing.T) {
	l := &ledger.Ledger{Events: []ledger.Event{
		{Type: "promoted", Line: "spring-framework-6.2.x", SetID: "s", Coordinates: []string{"x@1"}, CVEs: []string{"CVE-2024-38816"}, At: "t"},
		promoted("set-2", "CVE-1999-0001"),
	}}
	rec := Compute(inputs(t, l))
	if len(rec.Fixed) != 0 {
		t.Fatalf("fixed %v, want none", rec.Fixed)
	}
}
