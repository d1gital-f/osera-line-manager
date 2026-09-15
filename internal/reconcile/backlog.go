// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/graph"
	"github.com/d1gital-f/osera-line-manager/internal/scan"
)

// scanStamp is the file that remembers when a line was last scanned.
func (r *Reconciler) scanStamp(lineID string) string {
	return r.cachePath("scan-" + lineID + ".stamp")
}

// needsScan says whether the line's graph is scanned this pass: always when the
// graph was just built or the line has no entry yet, otherwise when the last
// scan is older than the rescan interval.
func needsScan(stamp string, justBuilt, hasEntries bool, interval time.Duration, now time.Time) bool {
	if justBuilt || !hasEntries {
		return true
	}
	raw, err := os.ReadFile(stamp)
	if err != nil {
		return true
	}
	when, _, _ := strings.Cut(strings.TrimSpace(string(raw)), " ")
	last, err := time.Parse(time.RFC3339, when)
	if err != nil {
		return true
	}
	return now.Sub(last) >= interval
}

// scanDecision says whether the line is scanned this pass and why, in words for the log.
func (r *Reconciler) scanDecision(p *pass, ln book.Line) (bool, string) {
	justBuilt := p.staged[graphPath(ln.ID)] != nil
	hasEntries := len(p.book.ForLine(ln.ID)) > 0
	interval := r.cfg.RescanInterval
	if justBuilt {
		return true, "is due: its graph was built this pass"
	}
	if !hasEntries {
		return true, "is due: it has no entry in the backlog yet"
	}
	raw, err := os.ReadFile(r.scanStamp(ln.ID))
	if err != nil {
		return true, "is due: no scan is recorded since the restart"
	}
	when, inputs, _ := strings.Cut(strings.TrimSpace(string(raw)), " ")
	last, err := time.Parse(time.RFC3339, when)
	if err != nil {
		return true, "is due: the scan record is unreadable"
	}
	if inputs != r.scanInputs() {
		return true, "is due: the rules file or the advisory file changed since its last scan"
	}
	if r.now().Sub(last) >= interval {
		return true, fmt.Sprintf("is due: last scanned %s, scanned again every %s", last.UTC().Format("2 Jan 15:04"), interval)
	}
	return false, fmt.Sprintf("last scanned %s, next %s", last.UTC().Format("2 Jan 15:04"), last.Add(interval).UTC().Format("2 Jan 15:04"))
}

// scanInputs is a digest of what shapes a scan besides the graph: the rules file and,
// on dev, the advisory file. A scan record carries it, so a change to either scans
// every line again on the next pass, in production as on dev.
func (r *Reconciler) scanInputs() string {
	h := sha256.New()
	for _, rel := range []string{filepath.Join("rules", "prioritisation.yaml"), filepath.FromSlash(r.cfg.DevAdvisories)} {
		if rel == "" {
			continue
		}
		raw, err := os.ReadFile(r.path(rel))
		if err != nil {
			continue
		}
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// scanLine scans the line's graph and merges the result into the backlog. The caller decided it is due.
func (r *Reconciler) scanLine(ctx context.Context, p *pass, ln book.Line) error {
	// 1. the rules
	if p.rules == nil {
		Lowf("! %s: no rules file in the repository, the scan is skipped", ln.ID)
		return nil
	}

	// 2. the graph's components
	g, err := graph.Read(r.path(filepath.FromSlash(graphPath(ln.ID))))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logf("! %s: no graph yet, nothing to scan", ln.ID)
			return nil
		}
		return err
	}
	var components []scan.Component
	for _, c := range g.Components {
		components = append(components, scan.Component{Group: c.Group, Artifact: c.Artifact, Version: c.Version})
	}

	// 3. grype over the graph file, or the four sources one by one, then the rules
	devAdvisories := ""
	if r.cfg.DevAdvisories != "" {
		devAdvisories = r.path(filepath.FromSlash(r.cfg.DevAdvisories))
	}
	started := r.now()
	findings, err := r.findings(ctx, ln.ID, devAdvisories, components)
	if err != nil {
		return fmt.Errorf("line %s: %w", ln.ID, err)
	}
	split := scan.Apply(ln.ID, findings, p.rules)
	for _, d := range split.Duplicates {
		logf("!   %s: %s", ln.ID, d)
	}
	logf("    %s, in %s", scanSummary(ln.ID, findings, split), seconds(r.now().Sub(started)))

	// 4. merged into the backlog, the file's memory kept; what moved, said
	before := p.book.ForLine(ln.ID)
	p.book.Entries = mergeScan(p.book.Entries, ln.ID, split.Entries)
	logf("    %s: %s", ln.ID, scanDelta(before, p.book.ForLine(ln.ID)))
	excluded, err := r.mergeExcluded(ln.ID, split.Excluded)
	if err != nil {
		return err
	}

	// 5. the three files, staged
	header := scan.Header{Title: p.book.Title, StandardsPack: p.book.StandardsPack, Generated: p.asOf}
	err = r.stageBacklog(p, ln.ID, header, excluded)
	if err != nil {
		return err
	}

	// 6. the stamp is remembered and written once the pass has committed: a result that never
	//    reaches the repository is scanned again next pass
	p.scanned = append(p.scanned, ln.ID)
	return nil
}

// findings runs the scanner the configuration chose, Grype over the graph file or the four
// sources over the components; a test can put its own function here.
func (r *Reconciler) findings(ctx context.Context, lineID, devAdvisories string, components []scan.Component) ([]scan.Finding, error) {
	if r.scanFn != nil {
		return r.scanFn(ctx, lineID, components)
	}
	if r.grype != nil {
		r.grype.DevAdvisories = devAdvisories
		err := r.grype.UpdateDB(ctx)
		if err != nil {
			return nil, fmt.Errorf("line %s: %w", lineID, err)
		}
		logf("    %s: scanning %d libraries with grype %s", lineID, len(components), r.grype.Version(ctx))
		return r.grype.Scan(ctx, r.path(filepath.FromSlash(graphPath(lineID))), components)
	}
	r.scanner.DevAdvisories = devAdvisories
	logf("    %s: scanning %d libraries with the four sources, OSV, CISA KEV, FIRST EPSS and NVD", lineID, len(components))
	return r.scanner.Scan(ctx, components)
}

// writeStamps records the scans of a pass that reached the repository (or a dry run's).
func (r *Reconciler) writeStamps(p *pass) error {
	if r.cfg.Dry {
		return nil
	}
	for _, lineID := range p.scanned {
		err := os.WriteFile(r.scanStamp(lineID), []byte(r.now().UTC().Format(time.RFC3339)+" "+r.scanInputs()+"\n"), 0o644)
		if err != nil {
			return err
		}
	}
	return nil
}

// mergeScan puts a line's scanned entries into the backlog: an entry already
// there keeps its status and the fields that go with it and takes the scan's
// facts, a new one is added open, an entry the scan no longer finds stays.
func mergeScan(existing []book.Entry, lineID string, scanned []book.Entry) []book.Entry {
	// 1. the entries already there, by key
	index := map[string]int{}
	for i, e := range existing {
		for _, l := range e.Lines {
			index[entryKey(l, e.CVE, e.Library)] = i
		}
	}

	// 2. each scanned entry: refreshed in place or added
	out := append([]book.Entry{}, existing...)
	for _, s := range scanned {
		i, known := index[entryKey(lineID, s.CVE, s.Library)]
		if !known {
			s.Status = book.EntryOpen
			out = append(out, s)
			continue
		}
		e := out[i]
		e.Version = s.Version
		e.CVSS = s.CVSS
		e.CVSSVersion = s.CVSSVersion
		e.CISAKEV = s.CISAKEV
		e.EPSSPercentile = s.EPSSPercentile
		e.Priority = s.Priority
		e.Why = s.Why
		e.Summary = s.Summary
		out[i] = e
	}
	return out
}

// excludedFile is cve-excluded.json as read back.
type excludedFile struct {
	Entries []scan.Excluded `json:"entries"`
}

// mergeExcluded replaces the line's excluded entries with the scan's and keeps the other lines'.
func (r *Reconciler) mergeExcluded(lineID string, scanned []scan.Excluded) ([]scan.Excluded, error) {
	// 1. the file as it is
	var f excludedFile
	raw, err := os.ReadFile(r.path("cve-excluded.json"))
	if err == nil {
		err = json.Unmarshal(raw, &f)
		if err != nil {
			return nil, fmt.Errorf("reading cve-excluded.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// 2. the other lines' entries, then this line's from the scan
	var out []scan.Excluded
	for _, e := range f.Entries {
		if !contains(e.Lines, lineID) {
			out = append(out, e)
		}
	}
	return append(out, scanned...), nil
}

// stageBacklog writes cve-backlog.json, cve-excluded.json and cve-backlog.md and stages them.
func (r *Reconciler) stageBacklog(p *pass, lineID string, header scan.Header, excluded []scan.Excluded) error {
	// 1. the three files as they are, so a rewrite that only moves the stamp is not a change
	backlogPath := r.path("cve-backlog.json")
	excludedPath := r.path("cve-excluded.json")
	tablePath := r.path("cve-backlog.md")
	oldBacklog, _ := os.ReadFile(backlogPath)
	oldExcluded, _ := os.ReadFile(excludedPath)
	oldTable, _ := os.ReadFile(tablePath)

	// 2. the two JSON files, written by the scan package in its order
	err := scan.WriteBacklog(backlogPath, header, p.book.Entries)
	if err != nil {
		return err
	}
	err = scan.WriteExcluded(excludedPath, header, excluded)
	if err != nil {
		return err
	}
	rawBacklog, err := os.ReadFile(backlogPath)
	if err != nil {
		return err
	}
	rawExcluded, err := os.ReadFile(excludedPath)
	if err != nil {
		return err
	}
	p.book.Generated = header.Generated
	rawTable := []byte(table(p.book))

	// 3. nothing but the stamps moved: the old files stay, nothing is staged
	if sameButForGenerated(oldBacklog, rawBacklog) && sameButForGenerated(oldExcluded, rawExcluded) && sameTableButForGenerated(oldTable, rawTable) {
		err = os.WriteFile(backlogPath, oldBacklog, 0o644)
		if err != nil {
			return err
		}
		return os.WriteFile(excludedPath, oldExcluded, 0o644)
	}

	// 4. staged, the readable table too
	err = r.stage(p, lineID, "cve-backlog.json", rawBacklog)
	if err != nil {
		return err
	}
	err = r.stage(p, lineID, "cve-excluded.json", rawExcluded)
	if err != nil {
		return err
	}
	return r.stage(p, lineID, "cve-backlog.md", rawTable)
}

// sameButForGenerated compares two backlog files ignoring their generated stamp.
func sameButForGenerated(a, b []byte) bool {
	var ra, rb map[string]any
	if json.Unmarshal(a, &ra) != nil || json.Unmarshal(b, &rb) != nil {
		return false
	}
	delete(ra, "generated")
	delete(rb, "generated")
	ja, _ := json.Marshal(ra)
	jb, _ := json.Marshal(rb)
	return string(ja) == string(jb)
}

// sameTableButForGenerated compares two readable tables ignoring the line that carries the stamp.
func sameTableButForGenerated(a, b []byte) bool {
	strip := func(raw []byte) string {
		var kept []string
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "Generated ") {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, "\n")
	}
	return len(a) > 0 && strip(a) == strip(b)
}

// replaceEntries puts a line's entries as the status computation left them back
// into the backlog, and stages the file when anything moved.
func (r *Reconciler) replaceEntries(p *pass, lineID string, entries []book.Entry) {
	// 1. the new statuses, by key
	byKey := map[string]book.Entry{}
	for _, e := range entries {
		byKey[entryKey(lineID, e.CVE, e.Library)] = e
	}

	// 2. in place, this line's entries only, remembering whether anything changed. Another
	//    line can carry the same CVE on the same library at its own version: it is not touched.
	changed := false
	for i, e := range p.book.Entries {
		if !contains(e.Lines, lineID) {
			continue
		}
		n, found := byKey[entryKey(lineID, e.CVE, e.Library)]
		if !found {
			continue
		}
		if e.Status != n.Status || e.Repository != n.Repository || e.FixedBy != n.FixedBy || e.FixedAt != n.FixedAt || e.Producer != n.Producer || e.Reason != n.Reason {
			changed = true
		}
		p.book.Entries[i] = n
	}
	if !changed {
		return
	}

	// 3. the files, staged again with the statuses
	header := scan.Header{Title: p.book.Title, StandardsPack: p.book.StandardsPack, Generated: p.asOf}
	excluded, err := r.mergeExcluded("", nil)
	if err != nil {
		Lowf("! %s: %v", lineID, err)
		return
	}
	err = r.stageBacklog(p, lineID, header, excluded)
	if err != nil {
		Lowf("! %s: %v", lineID, err)
	}
}

// table renders the backlog as one Markdown table, one row per entry.
func table(b *book.Book) string {
	var sb strings.Builder
	sb.WriteString("# " + b.Title + "\n\n")
	sb.WriteString("Generated " + b.Generated + ", entry schema " + b.SchemaVersion + ". Written by the line manager, never by hand.\n\n")
	sb.WriteString("| CVE | Library | Version | Line | CVSS | KEV | EPSS | Priority | Status | Fixed by |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, e := range b.Entries {
		epss := ""
		if e.EPSSPercentile != nil {
			epss = fmt.Sprintf("%.3f", *e.EPSSPercentile)
		}
		kev := "no"
		if e.CISAKEV {
			kev = "yes"
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %.1f (v%s) | %s | %s | %s | %s | %s |\n",
			e.CVE, e.Library, e.Version, strings.Join(e.Lines, " "), e.CVSS, e.CVSSVersion, kev, epss, e.Priority, e.Status, e.FixedBy)
	}
	return sb.String()
}
