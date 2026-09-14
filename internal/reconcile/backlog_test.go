// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import "testing"

// A rewrite that only moves the generated stamp is not a change, in the JSON files and in the table.
func TestSameButForGenerated(t *testing.T) {
	a := []byte(`{"generated":"2026-09-14T19:57:50Z","entries":[{"cve":"CVE-1"}]}`)
	b := []byte(`{"generated":"2026-09-14T21:09:34Z","entries":[{"cve":"CVE-1"}]}`)
	c := []byte(`{"generated":"2026-09-14T21:09:34Z","entries":[{"cve":"CVE-2"}]}`)
	if !sameButForGenerated(a, b) {
		t.Fatal("the stamp alone must not count")
	}
	if sameButForGenerated(a, c) {
		t.Fatal("a different entry must count")
	}
	ta := []byte("# Backlog\nGenerated 2026-09-14T19:57:50Z, entry schema 0.6.0.\n| CVE-1 |\n")
	tb := []byte("# Backlog\nGenerated 2026-09-14T21:09:34Z, entry schema 0.6.0.\n| CVE-1 |\n")
	tc := []byte("# Backlog\nGenerated 2026-09-14T21:09:34Z, entry schema 0.6.0.\n| CVE-2 |\n")
	if !sameTableButForGenerated(ta, tb) || sameTableButForGenerated(ta, tc) || sameTableButForGenerated(nil, tb) {
		t.Fatal("the table compare is wrong")
	}
}
