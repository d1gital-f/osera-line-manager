// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/intent"
	"github.com/d1gital-f/osera-line-manager/internal/rules"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// pass is the state of one pass: what was read, what changed, what to write.
type pass struct {
	asOf        string
	bookVersion string
	head        string
	lines       []book.Line
	rules       *rules.Rules
	book        *book.Book
	// before remembers each entry's status as the file had it, keyed by CVE and library.
	before map[string]string
	// staged are the files to commit, repository path to content.
	staged map[string][]byte
	// changedLines names the lines something was staged for.
	changedLines []string
	// backlogChanged says cve-backlog.json is among the staged files, which is what a tag is for.
	backlogChanged bool
	// failed names the lines whose graph or scan failed this pass: logged, skipped, retried next pass.
	failed map[string]error
	// scanned names the lines scanned this pass; their stamps are written once the pass has committed.
	scanned []string
	// own is the intent note found at the start of the pass, nil when none.
	own     *intent.Intent
	records []status.Record
}

// Once runs one pass and returns the records. Ten steps, each safe to repeat.
func (r *Reconciler) Once(ctx context.Context) ([]status.Record, error) {
	return r.OnceFor(ctx, "")
}

// OnceFor is Once with the reason the pass runs, said in the log: the timer, a webhook, a hand.
func (r *Reconciler) OnceFor(ctx context.Context, reason string) ([]status.Record, error) {
	r.passes++
	started := r.now()
	p := &pass{asOf: started.UTC().Format(time.RFC3339), staged: map[string][]byte{}, before: map[string]string{}}

	// 1. the inputs: the clone at origin's main, the lines, the rules, the intent note
	err := r.readInputs(ctx, p)
	if err != nil {
		return nil, err
	}
	since := ""
	if !r.lastEnd.IsZero() {
		since = "; the last pass ended " + seconds(started.Sub(r.lastEnd)) + " ago"
	}
	if reason == "" {
		reason = "on request"
	}
	Lowf("pass %d starts %s: backlog at %s (tag %s), %d lines: %s%s", r.passes, reason, short(p.head), tagWords(p.bookVersion), len(p.lines), lineNames(p.lines), since)
	records, err := r.run(ctx, p)
	if err != nil {
		// a pass that fails after writing into the worktree leaves the repository's own files
		// as they are on main, the graphs excepted, and no scan stamp: the next pass starts clean
		discardErr := r.discard(p)
		if discardErr != nil {
			Lowf("pass %d: discarding the failed pass: %v", r.passes, discardErr)
		}
		return nil, err
	}
	r.lastEnd = r.now()
	next := ""
	if !r.nextAt.IsZero() {
		next = "; next pass on the timer at " + r.nextAt.UTC().Format("15:04:05Z")
	}
	Lowf("pass %d done in %s%s", r.passes, seconds(r.lastEnd.Sub(started)), next)
	return records, nil
}

// tagWords names the tag in a log line, or says there is none.
func tagWords(tag string) string {
	if tag == "" {
		return "none"
	}
	return tag
}

// lineNames lists the line ids in a log line.
func lineNames(lines []book.Line) string {
	var ids []string
	for _, ln := range lines {
		ids = append(ids, ln.ID)
	}
	return strings.Join(ids, ", ")
}

// run is the pass after its inputs, steps 2 to 10.
func (r *Reconciler) run(ctx context.Context, p *pass) ([]status.Record, error) {
	var err error

	// 2. the graph of every line, resolved when missing or built from another anchor
	p.failed = map[string]error{}
	var built, kept []string
	for _, ln := range p.lines {
		err = r.ensureGraph(ctx, p, ln)
		if err != nil {
			// one line's resolve failing does not stop the others; it is retried next pass
			Lowf("%s: graph: %v (skipped this pass)", ln.ID, err)
			p.failed[ln.ID] = err
			continue
		}
		if p.staged[graphPath(ln.ID)] != nil {
			built = append(built, ln.ID)
		} else {
			kept = append(kept, ln.ID)
		}
	}
	logf("%s", graphsWords(built, kept))

	// 3. the scan of every line whose graph is new or whose last scan is old, merged into the backlog
	var due []book.Line
	var reasons []string
	for _, ln := range p.lines {
		if p.failed[ln.ID] != nil {
			continue
		}
		isDue, why := r.scanDecision(p, ln)
		reasons = append(reasons, ln.ID+" "+why)
		if isDue {
			due = append(due, ln)
		}
	}
	logf("%s", rescanWords(due, reasons))
	for _, ln := range due {
		err = r.scanLine(ctx, p, ln)
		if err != nil {
			Lowf("%s: scan: %v (skipped this pass)", ln.ID, err)
			p.failed[ln.ID] = err
		}
	}

	// 4. the board and the release repository, once each
	issues, err := r.readBoard(ctx)
	if err != nil {
		return nil, err
	}
	promoted, err := r.readPromotions(ctx, p)
	if err != nil {
		return nil, err
	}

	// 5. one record per line
	for _, ln := range p.lines {
		if p.failed[ln.ID] != nil {
			continue
		}
		rec := status.Compute(status.Inputs{
			Line:              ln,
			BookVersion:       p.bookVersion,
			AsOf:              p.asOf,
			Book:              p.book,
			Promoted:          promoted,
			Issues:            issues,
			BacklogRepository: r.cfg.Repo,
			Consume:           ln.Consume,
		})
		for _, words := range transitions(ln.ID, p.before, rec.Entries) {
			logf("%s: %s", ln.ID, words)
		}
		r.replaceEntries(p, ln.ID, rec.Entries)

		// 6. the BOM, when the promoted set of the line moved
		rec, err = r.ensureBOM(ctx, p, ln, rec, promoted)
		if err != nil {
			return nil, err
		}
		p.records = append(p.records, rec)
	}

	// 7. the line rows and the status files, a row never contradicting the backlog file
	err = r.stageOutputs(p)
	if err != nil {
		return nil, err
	}

	// 8. the pull request, merged by the line manager, and the tag when the backlog changed
	err = r.publish(ctx, p)
	if err != nil {
		return nil, err
	}
	err = r.writeStamps(p)
	if err != nil {
		return nil, err
	}

	// 9. the issues of the entries that became fixed or not remediable, closed; the reopened ones
	err = r.settleIssues(ctx, p, issues)
	if err != nil {
		return nil, err
	}
	err = r.moveLanes(ctx, p, issues)
	if err != nil {
		return nil, err
	}

	// 10. one line per line
	for _, rec := range p.records {
		Lowf("%s", recordWords(rec))
	}
	return p.records, nil
}

// readInputs fetches the clone and reads the line file, the rules and the backlog as they are.
func (r *Reconciler) readInputs(ctx context.Context, p *pass) error {
	// 1. the clone at origin's main, or the local directory as it is
	if r.clone != nil {
		err := r.auth(ctx)
		if err != nil {
			return err
		}
		res, err := r.clone.Fetch(ctx)
		if err != nil {
			return fmt.Errorf("fetching the backlog: %w", err)
		}
		if res.Reset {
			logf("the clone was reset to origin, it had moved on its own")
		}
		p.head, _, err = r.clone.Head()
		if err != nil {
			return err
		}
		tag, _, err := r.clone.LatestTag()
		if err == nil {
			p.bookVersion = tag
		}
	} else {
		p.bookVersion = r.cfg.LocalVersion
	}

	// 2. the intent note: a commit the clone now carries is done with, anything else is remembered
	own, err := intent.Read(r.cachePath("intent.json"))
	if err == nil {
		if own.Kind == "commit" && r.clone != nil && p.head == own.Ref {
			err = intent.Clear(r.cachePath("intent.json"))
			if err != nil {
				return err
			}
		} else {
			p.own = own
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// 3. the lines
	p.lines, err = book.ReadLines(r.path("supported-lines.csv"))
	if err != nil {
		return err
	}

	// 4. the rules, when the repository carries them
	p.rules, err = rules.Load(r.path("rules", "prioritisation.yaml"))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		p.rules = nil
	}

	// 5. the backlog as it is, empty on a first pass
	p.book, err = readBacklog(r.path("cve-backlog.json"))
	if err != nil {
		return err
	}
	for _, e := range p.book.Entries {
		for _, l := range e.Lines {
			p.before[entryKey(l, e.CVE, e.Library)] = e.Status
		}
	}
	return nil
}

// readBacklog reads cve-backlog.json, an empty backlog when the file is not there yet.
func readBacklog(path string) (*book.Book, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &book.Book{SchemaVersion: book.SchemaVersion, Title: "OSERA CVE backlog", StandardsPack: "OSERA-SP-0.1.0", Entries: []book.Entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return book.Read(path)
}

// entryKey names one entry on one line.
func entryKey(line, cve, library string) string {
	return line + " " + cve + " " + library
}

// stage remembers a file to commit, and writes it into the work directory so
// the rest of the pass reads what will be committed.
func (r *Reconciler) stage(p *pass, lineID, relPath string, content []byte) error {
	p.staged[relPath] = content
	if relPath == "cve-backlog.json" {
		p.backlogChanged = true
	}
	if lineID != "" && !contains(p.changedLines, lineID) {
		p.changedLines = append(p.changedLines, lineID)
	}
	full := r.path(relPath)
	err := os.MkdirAll(filepathDir(full), 0o755)
	if err != nil {
		return err
	}
	return os.WriteFile(full, content, 0o644)
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// short is the first seven characters of a commit id, the whole id when shorter.
func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// discard puts the worktree back as main has it for every file a failed pass wrote,
// the graphs excepted (a graph is kept, it is expensive and the next pass checks it).
func (r *Reconciler) discard(p *pass) error {
	if r.clone == nil {
		return nil
	}
	var paths []string
	for path := range p.staged {
		if strings.HasPrefix(path, "graphs/") {
			continue
		}
		paths = append(paths, path)
	}
	// the backlog files are written to disk before they are staged, so a failure between
	// the write and the stage leaves them too: always put the three back
	for _, path := range []string{"cve-backlog.json", "cve-excluded.json", "cve-backlog.md", "supported-lines.csv"} {
		if !contains(paths, path) {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return r.clone.Restore(paths)
}
