// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import "testing"

// Two line files that differ in as_of only are the same rows; any other cell differing is not.
func TestSameRowsButForTime(t *testing.T) {
	header := "line_id,ecosystem,anchor,components,scope,source,status,book_version,as_of,in_scope,fixed,in_progress,open,not_remediable,consume\n"
	a := header + "dev-1.0.x,maven,g:bom@1,g:a@1,dev,test,not fixed,v1,2026-09-14T20:00:00Z,3,0,0,3,0,\n"
	b := header + "dev-1.0.x,maven,g:bom@1,g:a@1,dev,test,not fixed,v1,2026-09-14T20:10:00Z,3,0,0,3,0,\n"
	c := header + "dev-1.0.x,maven,g:bom@1,g:a@1,dev,test,in progress,v1,2026-09-14T20:10:00Z,3,1,0,2,0,\n"
	if !sameRowsButForTime([]byte(a), []byte(b)) {
		t.Fatal("as_of alone must not count as a change")
	}
	if sameRowsButForTime([]byte(a), []byte(c)) {
		t.Fatal("a moved count is a change")
	}
	if sameRowsButForTime([]byte(a), []byte(header)) {
		t.Fatal("a missing row is a change")
	}
}
