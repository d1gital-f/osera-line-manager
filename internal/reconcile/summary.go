// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"fmt"
	"github.com/d1gital-f/osera-line-manager/internal/book"
	"sort"
	"strconv"
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

// boardWords is the board in one line with the claimed cards named: which issue, in which
// patch repository, a producer has taken.
func boardWords(issues []status.Issue, backlogRepository string) string {
	var closed, declared int
	byRepo := map[string][]string{}
	var repos []string
	for _, is := range issues {
		if is.Repository != "" && is.Repository != backlogRepository {
			if _, seen := byRepo[is.Repository]; !seen {
				repos = append(repos, is.Repository)
			}
			byRepo[is.Repository] = append(byRepo[is.Repository], "#"+strconv.Itoa(is.Number))
		}
		if is.State == "CLOSED" {
			closed++
		}
		if is.NotRemediable {
			declared++
		}
	}
	claimed := 0
	var parts []string
	for _, repo := range repos {
		claimed += len(byRepo[repo])
		parts = append(parts, strings.Join(byRepo[repo], " ")+" in "+repo)
	}
	out := fmt.Sprintf("board: %d cards; %d claimed by a producer", len(issues), claimed)
	if claimed > 0 {
		out += " (moved to a patch repository): " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s; %d closed; %d marked not remediable", out, closed, declared)
}

// graphsWords says what happened to the graphs this pass.
func graphsWords(built, kept []string) string {
	if len(built) == 0 {
		return fmt.Sprintf("graphs: all %d kept, nothing changed in the lines", len(kept))
	}
	return fmt.Sprintf("graphs: %d built (%s), %d kept", len(built), strings.Join(built, ", "), len(kept))
}

// rescanWords says which lines are scanned this pass and why, and when the others are next.
func rescanWords(due []book.Line, reasons []string) string {
	if len(due) == 0 {
		return "rescan: none due; " + strings.Join(reasons, "; ")
	}
	return "rescan: " + strings.Join(reasons, "; ")
}

// scanDelta compares a line's entries before and after a scan was merged in.
func scanDelta(before, after []book.Entry) string {
	was := map[string]book.Entry{}
	for _, e := range before {
		was[e.CVE+" "+e.Library] = e
	}
	var fresh, moved []string
	for _, e := range after {
		old, found := was[e.CVE+" "+e.Library]
		if !found {
			fresh = append(fresh, e.CVE+" in "+shortLibrary(e.Library))
			continue
		}
		if old.Priority != e.Priority {
			moved = append(moved, e.CVE+" "+old.Priority+" to "+e.Priority)
		}
	}
	if len(fresh) == 0 && len(moved) == 0 {
		return fmt.Sprintf("compared with the backlog: nothing new, %d entries unchanged", len(after))
	}
	out := "compared with the backlog: "
	if len(fresh) > 0 {
		out += fmt.Sprintf("%d new (%s)", len(fresh), firstFew(fresh, 6))
	}
	if len(moved) > 0 {
		if len(fresh) > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d changed priority (%s)", len(moved), firstFew(moved, 6))
	}
	return out
}

// transitions says which entries of a line changed status this pass, grouped by the
// move, the entries named: "3 entries went from open to in progress: CVE-1 in a, ...".
func transitions(lineID string, before map[string]string, entries []book.Entry) []string {
	groups := map[string][]string{}
	var order []string
	for _, e := range entries {
		was := before[entryKey(lineID, e.CVE, e.Library)]
		if was == "" || was == e.Status {
			continue
		}
		key := "from " + was + " to " + e.Status
		if e.Status == book.EntryFixed && e.FixedBy != "" {
			key += " by " + e.FixedBy
		}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], e.CVE+" in "+shortLibrary(e.Library))
	}
	var out []string
	for _, key := range order {
		names := groups[key]
		noun := "entries went"
		if len(names) == 1 {
			noun = "entry went"
		}
		out = append(out, fmt.Sprintf("%d %s %s: %s", len(names), noun, key, firstFew(names, 6)))
	}
	return out
}

// releasesWords is the release repository in one line: what is there, what is new, what
// waits for its evidence file.
func releasesWords(coords, patched, withEvidence int, fresh, without []string) string {
	out := fmt.Sprintf("release repository: %d coordinates, %d patched jars, %d with an evidence file", coords, patched, withEvidence)
	if len(fresh) > 0 {
		out += fmt.Sprintf("; %d new since the last pass: %s", len(fresh), firstFew(fresh, 6))
	}
	if len(without) > 0 {
		out += fmt.Sprintf("; %d without an evidence file yet (%s), they fix nothing until it appears", len(without), firstFew(without, 6))
	}
	return out
}

// changesWords names the staged files in words: the four backlog files by name, the
// status files and the graphs counted.
func changesWords(paths []string) string {
	var named []string
	statuses, graphs, others := 0, 0, 0
	for _, p := range paths {
		switch {
		case strings.HasPrefix(p, "status/"):
			statuses++
		case strings.HasPrefix(p, "graphs/"):
			graphs++
		case p == "supported-lines.csv" || p == "cve-backlog.json" || p == "cve-excluded.json" || p == "cve-backlog.md":
			named = append(named, p)
		default:
			others++
		}
	}
	if graphs > 0 {
		named = append(named, fmt.Sprintf("%d graph file(s)", graphs))
	}
	if statuses > 0 {
		named = append(named, fmt.Sprintf("%d status file(s)", statuses))
	}
	if others > 0 {
		named = append(named, fmt.Sprintf("%d other file(s)", others))
	}
	return strings.Join(named, ", ")
}

// recordWords is a line's state at the end of the pass in one sentence.
func recordWords(rec status.Record) string {
	out := fmt.Sprintf("%s: %s. %d in scope: %d fixed, %d in progress, %d open, %d not remediable", rec.Line, rec.Status, rec.InScope, len(rec.Fixed), len(rec.InProgress), len(rec.Open), len(rec.NotRemediable))
	if len(rec.Discrepancies) > 0 {
		out += fmt.Sprintf("; %d discrepancies for a person (status/%s.json)", len(rec.Discrepancies), rec.Line)
	}
	if rec.Consume != "" {
		return out + ". Banks consume " + rec.Consume + "."
	}
	return out + ". Nothing to consume yet."
}

// shortLibrary is the artifact without its group, enough in a log line.
func shortLibrary(library string) string {
	if i := strings.LastIndex(library, ":"); i >= 0 {
		return library[i+1:]
	}
	return library
}

// firstFew joins up to n names, then says how many more.
func firstFew(names []string, n int) string {
	if len(names) <= n {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:n], ", ") + fmt.Sprintf(" and %d more", len(names)-n)
}
