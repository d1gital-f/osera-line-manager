// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)


// Two entries alike in everything but their line keep one order whichever was
// scanned last: a rescan of several lines must write the same file.
func TestSortIsStableAcrossLines(t *testing.T) {
	a := Excluded{CVE: "CVE-2024-1", Library: "org.example:lib", Version: "1.0", Lines: []string{"line-b"}, Priority: "P1", CVSS: 7.5, Reason: "below the bar"}
	b := Excluded{CVE: "CVE-2024-1", Library: "org.example:lib", Version: "1.0", Lines: []string{"line-a"}, Priority: "P1", CVSS: 7.5, Reason: "below the bar"}
	one := []Excluded{a, b}
	two := []Excluded{b, a}
	sortExcluded(one)
	sortExcluded(two)
	if one[0].Lines[0] != "line-a" || two[0].Lines[0] != "line-a" {
		t.Fatalf("order depends on the scan order: %v / %v", one[0].Lines, two[0].Lines)
	}
	c := book.Entry{CVE: "CVE-2024-1", Library: "org.example:lib", Version: "1.1", Lines: []string{"line-a"}, Priority: "P1", CVSS: 7.5}
	d := book.Entry{CVE: "CVE-2024-1", Library: "org.example:lib", Version: "1.0", Lines: []string{"line-a"}, Priority: "P1", CVSS: 7.5}
	es := []book.Entry{c, d}
	sortEntries(es)
	if es[0].Version != "1.0" {
		t.Fatalf("the version must order the tie: %v", es)
	}
}
