// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/scan"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// scanSummary is the one line that says what a scan found: the findings, the
// libraries they sit on, the severity bands, what the rules kept and why the
// rest went out.
func scanSummary(lineID string, findings []scan.Finding, split scan.Split) string {
	// 1. the bands, from the score the rules read
	var critical, high, medium, low, unscored int
	libraries := map[string]bool{}
	for _, f := range findings {
		libraries[f.Component.Group+":"+f.Component.Artifact] = true
		switch {
		case f.Score == nil:
			unscored++
		case *f.Score >= 9.0:
			critical++
		case *f.Score >= 7.0:
			high++
		case *f.Score >= 4.0:
			medium++
		default:
			low++
		}
	}

	// 2. the reasons the rules gave, counted by their first words
	reasons := map[string]int{}
	for _, e := range split.Excluded {
		reasons[reasonWords(e.Reason)]++
	}
	var parts []string
	for word, n := range reasons {
		parts = append(parts, fmt.Sprintf("%s %d", word, n))
	}
	sort.Strings(parts)

	// 3. the line
	bands := fmt.Sprintf("%d critical, %d high, %d medium, %d low", critical, high, medium, low)
	if unscored > 0 {
		bands += fmt.Sprintf(", %d unscored", unscored)
	}
	out := fmt.Sprintf("%s: %d findings on %d libraries: %s; %d applicable by the rules, %d excluded", lineID, len(findings), len(libraries), bands, len(split.Entries), len(split.Excluded))
	if len(parts) > 0 {
		out += " (" + strings.Join(parts, ", ") + ")"
	}
	return out
}

// reasonWords turns a reason sentence into the two or three words that name it.
func reasonWords(reason string) string {
	switch {
	case strings.Contains(reason, "curated list"):
		return "curated list"
	case strings.Contains(reason, "window"):
		return "below the bar"
	case strings.HasPrefix(reason, "unscored"):
		return "unscored"
	}
	return "other"
}

// boardSummary is the one line that says what the board holds.
func boardSummary(issues []status.Issue, backlogRepository string) string {
	var moved, closed, declared int
	for _, is := range issues {
		if is.Repository != "" && is.Repository != backlogRepository {
			moved++
		}
		if is.State == "CLOSED" {
			closed++
		}
		if is.NotRemediable {
			declared++
		}
	}
	return fmt.Sprintf("board: %d cards, %d in a patch repository, %d closed, %d labelled not remediable", len(issues), moved, closed, declared)
}
