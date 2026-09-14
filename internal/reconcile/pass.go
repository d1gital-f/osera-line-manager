// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	// own is the intent note found at the start of the pass, nil when none.
	own     *intent.Intent
	records []status.Record
}

// Once runs one pass and returns the records. Ten steps, each safe to repeat.
func (r *Reconciler) Once(ctx context.Context) ([]status.Record, error) {
	p := &pass{asOf: r.now().UTC().Format(time.RFC3339), staged: map[string][]byte{}, before: map[string]string{}}

	// 1. the inputs: the clone at origin's main, the lines, the rules, the intent note
	err := r.readInputs(ctx, p)
	if err != nil {
		return nil, err
	}

	// 2. the graph of every line, resolved when missing or built from another anchor
	for _, ln := range p.lines {
		err = r.ensureGraph(ctx, p, ln)
		if err != nil {
			return nil, err
		}
	}

	// 3. the scan of every line whose graph is new or whose last scan is old, merged into the backlog
	for _, ln := range p.lines {
		err = r.scanLine(ctx, p, ln)
		if err != nil {
			return nil, err
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
		r.replaceEntries(p, ln.ID, rec.Entries)

		// 6. the BOM, when the promoted set of the line moved
		rec, err = r.ensureBOM(ctx, p, ln, rec, promoted)
		if err != nil {
			return nil, err
		}
		p.records = append(p.records, rec)
	}

	// 7. the line rows and the status files
	err = r.stageOutputs(p)
	if err != nil {
		return nil, err
	}

	// 8. the pull request, merged by the line manager, and the tag when the backlog changed
	err = r.publish(ctx, p)
	if err != nil {
		return nil, err
	}

	// 9. the issues of the entries that became fixed or not remediable, closed; the reopened ones
	err = r.settleIssues(ctx, p, issues)
	if err != nil {
		return nil, err
	}

	// 10. one line per line
	for _, rec := range p.records {
		logf("line %s: %s, in scope %d, fixed %d, in progress %d, open %d, not remediable %d, discrepancies %d, consume %q",
			rec.Line, rec.Status, rec.InScope, len(rec.Fixed), len(rec.InProgress), len(rec.Open), len(rec.NotRemediable), len(rec.Discrepancies), rec.Consume)
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
