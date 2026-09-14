// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/scan"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

func score(v float64) *float64 {
	return &v
}

// The scan summary counts bands, libraries and the excluded reasons.
func TestScanSummary(t *testing.T) {
	c := func(a string) scan.Component { return scan.Component{Group: "g", Artifact: a, Version: "1"} }
	cases := []struct {
		name     string
		findings []scan.Finding
		split    scan.Split
		want     string
	}{
		{
			name: "bands and reasons",
			findings: []scan.Finding{
				{CVE: "CVE-1", Component: c("a"), Score: score(9.8)},
				{CVE: "CVE-2", Component: c("a"), Score: score(7.5)},
				{CVE: "CVE-3", Component: c("b"), Score: score(5.3)},
				{CVE: "CVE-4", Component: c("c"), Score: score(2.0)},
				{CVE: "CVE-5", Component: c("c")},
			},
			split: scan.Split{
				Entries:  []book.Entry{{CVE: "CVE-1"}, {CVE: "CVE-2"}},
				Excluded: []scan.Excluded{{Reason: "group g is not on the curated list"}, {Reason: "score 5.3, no signal in the 6.0 to 6.9 window"}, {Reason: "unscored, not on the KEV list"}},
			},
			want: "l: 5 findings on 3 libraries: 1 critical, 1 high, 1 medium, 1 low, 1 unscored; 2 applicable by the rules, 3 excluded (below the bar 1, curated list 1, unscored 1)",
		},
		{
			name: "nothing found",
			want: "l: 0 findings on 0 libraries: 0 critical, 0 high, 0 medium, 0 low; 0 applicable by the rules, 0 excluded",
		},
	}
	for _, tc := range cases {
		got := scanSummary("l", tc.findings, tc.split)
		if got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// The board summary counts the cards that moved, closed or were labelled.
func TestBoardSummary(t *testing.T) {
	issues := []status.Issue{
		{CVE: "CVE-1", Repository: "backlog", State: "OPEN"},
		{CVE: "CVE-2", Repository: "patch-x", State: "OPEN"},
		{CVE: "CVE-3", Repository: "patch-x", State: "CLOSED", NotRemediable: true},
	}
	got := boardSummary(issues, "backlog")
	want := "board: 3 cards, 2 in a patch repository, 1 closed, 1 labelled not remediable"
	if got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}
