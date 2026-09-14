// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/bom"
	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/intent"
	"github.com/d1gital-f/osera-line-manager/internal/repo"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// bomPath is where a line's BOM lives in the repository.
func bomPath(lineID string) string {
	return "bom/" + lineID + "/pom.xml"
}

// needsBOM says whether a new BOM is due: the promoted coordinates that fixed
// entries differ from what the last BOM pins. Nothing fixed means no BOM.
func needsBOM(pins []bom.Dependency, fixed []status.FixedEntry) bool {
	if len(fixed) == 0 {
		return false
	}
	want := map[string]bool{}
	for _, f := range fixed {
		want[f.Coordinate] = true
	}
	have := map[string]bool{}
	for _, d := range pins {
		have[d.Group+":"+d.Artifact+"@"+d.Version] = true
	}
	if len(want) != len(have) {
		return true
	}
	for k := range want {
		if !have[k] {
			return true
		}
	}
	return false
}

// ensureBOM builds, uploads and stages a new BOM when the line's promoted set
// moved, and puts its coordinate on the record.
func (r *Reconciler) ensureBOM(ctx context.Context, p *pass, ln book.Line, rec status.Record, promoted []status.Promotion) (status.Record, error) {
	// 1. what the last BOM pins
	var pins []bom.Dependency
	raw, err := os.ReadFile(r.path(filepath.FromSlash(bomPath(ln.ID))))
	if err == nil {
		pins, err = bom.Read(raw)
		if err != nil {
			return rec, fmt.Errorf("line %s: %w", ln.ID, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return rec, err
	}
	if !needsBOM(pins, rec.Fixed) {
		return rec, nil
	}

	// 2. the version, against the ones already in the release repository
	var existing []string
	for _, pr := range promoted {
		if pr.Coordinate.Group == bom.Group && pr.Coordinate.Artifact == bom.ArtifactID(ln.ID) {
			existing = append(existing, pr.Coordinate.Version)
		}
	}
	version := bom.Version(r.now(), existing)
	b, err := bom.Build(ln, rec.Fixed, version)
	if err != nil {
		return rec, err
	}
	content, err := b.Bytes()
	if err != nil {
		return rec, err
	}

	// 3. the upload, the intent written first, not in a dry run
	if r.cfg.Dry {
		logf("%s: dry run, would upload the BOM %s with %d pins", ln.ID, b.Coordinate(), len(b.Dependencies))
	} else {
		err = intent.Write(r.cachePath("intent.json"), intent.Intent{Kind: "bom", Line: ln.ID, Ref: b.Coordinate()})
		if err != nil {
			return rec, err
		}
		err = bom.Upload(ctx, r.nexus, r.cfg.Nexus.ReleaseRepository, b)
		if err != nil {
			return rec, err
		}
		Lowf("%s: BOM %s built with %d pins, uploaded to %s", ln.ID, b.Coordinate(), len(b.Dependencies), r.cfg.Nexus.ReleaseRepository)
	}

	// 4. the file staged, the coordinate on the record once it is really there
	err = r.stage(p, ln.ID, bomPath(ln.ID), content)
	if err != nil {
		return rec, err
	}
	if !r.cfg.Dry {
		rec.Consume = b.Coordinate()
	}
	return rec, nil
}

// stageOutputs writes the line rows and one status file per line, and stages
// them when they changed.
func (r *Reconciler) stageOutputs(p *pass) error {
	// 1. the guard: a row says what the backlog file says, or it is not written this pass
	var rows []status.Record
	for _, rec := range p.records {
		inFile := len(p.book.ForLine(rec.Line))
		if rec.InScope != inFile {
			Lowf("%s: discrepancy, the record has %d in scope and the backlog file %d entries, the row and the status file are not written this pass", rec.Line, rec.InScope, inFile)
			continue
		}
		rows = append(rows, rec)
	}

	// 2. the line rows
	linesPath := r.path("supported-lines.csv")
	before, err := os.ReadFile(linesPath)
	if err != nil {
		return err
	}
	err = WriteLines(linesPath, rows)
	if err != nil {
		return err
	}
	after, err := os.ReadFile(linesPath)
	if err != nil {
		return err
	}
	if string(before) != string(after) {
		err = r.stage(p, "", "supported-lines.csv", after)
		if err != nil {
			return err
		}
	}

	// 3. one status file per line, staged when its content moved
	for _, rec := range rows {
		raw, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		rel := "status/" + rec.Line + ".json"
		old, readErr := os.ReadFile(r.path(filepath.FromSlash(rel)))
		if readErr == nil && sameButForTime(old, raw) {
			continue
		}
		err = r.stage(p, rec.Line, rel, raw)
		if err != nil {
			return err
		}
	}
	return nil
}

// sameButForTime says two status files agree on everything but as_of, so a
// pass that found nothing new does not rewrite the file.
func sameButForTime(a, b []byte) bool {
	var ra, rb map[string]any
	if json.Unmarshal(a, &ra) != nil || json.Unmarshal(b, &rb) != nil {
		return false
	}
	delete(ra, "as_of")
	delete(rb, "as_of")
	ja, _ := json.Marshal(ra)
	jb, _ := json.Marshal(rb)
	return string(ja) == string(jb)
}

// publish commits what was staged as one pull request, merges it when validate
// is green, tags when the backlog changed, and fetches so the clone is at what
// was written. A dry run and a local run log what would happen.
func (r *Reconciler) publish(ctx context.Context, p *pass) error {
	if len(p.staged) == 0 {
		return nil
	}
	var paths []string
	for path := range p.staged {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	highf("staged %d files for the commit: %s", len(paths), strings.Join(paths, ", "))
	if r.cfg.Dry || r.clone == nil {
		logf("dry run, would commit %s", strings.Join(paths, ", "))
		return nil
	}

	// 1. the branch and the commit, the intent written first
	branch := "line-manager/pass"
	if len(p.changedLines) == 1 {
		branch = "line-manager/" + p.changedLines[0]
	}
	_, tree, err := r.clone.Head()
	if err != nil {
		return err
	}
	message := fmt.Sprintf("Line manager pass at %s: %s", p.asOf, strings.Join(paths, ", "))
	err = intent.Write(r.cachePath("intent.json"), intent.Intent{Kind: "commit", Line: strings.Join(p.changedLines, " "), Ref: branch})
	if err != nil {
		return err
	}
	commit, err := r.api.Commit(ctx, r.cfg.Owner, r.cfg.Repo, branch, repo.CommitRef{SHA: p.head, Tree: tree}, p.staged, message)
	if err != nil {
		return err
	}
	Lowf("committed %s on %s%s", commit.SHA[:7], branch, r.verifiedWords(ctx, commit.SHA))

	// 2. the pull request and its checks
	number, err := r.api.OpenPullRequest(ctx, r.cfg.Owner, r.cfg.Repo, branch, repo.Branch, "Line manager: "+strings.Join(p.changedLines, ", "), message)
	if err != nil {
		return err
	}
	Lowf("pull request #%d opened for %s", number, branch)
	waited := r.now()
	green, err := r.waitForChecks(ctx, commit.SHA)
	if err != nil {
		return err
	}
	if !green {
		logf("validate: red after %s, pull request #%d left open for a person", seconds(r.now().Sub(waited)), number)
		return r.api.Comment(ctx, r.cfg.Owner, r.cfg.Repo, number, "validate is not green on "+commit.SHA[:7]+", the line manager leaves this pull request for a person.")
	}
	logf("validate: green after %s", seconds(r.now().Sub(waited)))

	// 3. the merge, the fetch, the intent noted on the new head
	err = r.api.MergePullRequest(ctx, r.cfg.Owner, r.cfg.Repo, number)
	if err != nil {
		return err
	}
	Lowf("merged pull request #%d", number)
	err = r.auth(ctx)
	if err != nil {
		return err
	}
	_, err = r.clone.Fetch(ctx)
	if err != nil {
		return err
	}
	head, _, err := r.clone.Head()
	if err != nil {
		return err
	}
	err = intent.Write(r.cachePath("intent.json"), intent.Intent{Kind: "commit", Line: strings.Join(p.changedLines, " "), Ref: head})
	if err != nil {
		return err
	}

	// 4. the tag, when the backlog changed
	if !p.backlogChanged {
		return nil
	}
	tags, err := r.clone.Tags()
	if err != nil {
		return err
	}
	name := tagName(r.now(), tags)
	err = r.api.Tag(ctx, r.cfg.Owner, r.cfg.Repo, name, head)
	if err != nil {
		return err
	}
	Lowf("tagged %s at %s", name, head[:7])
	return nil
}

// verifiedWords says whether GitHub verified the commit it just made, in a log line.
func (r *Reconciler) verifiedWords(ctx context.Context, sha string) string {
	verified, err := r.api.Verified(ctx, r.cfg.Owner, r.cfg.Repo, sha)
	if err != nil {
		return ""
	}
	if verified {
		return " (verified by GitHub)"
	}
	return " (not verified by GitHub)"
}

// tagName is v followed by the date, with .2, .3 when the date is taken.
func tagName(now time.Time, existing []string) string {
	base := "v" + now.UTC().Format("2006.01.02")
	taken := map[string]bool{}
	for _, t := range existing {
		taken[t] = true
	}
	if !taken[base] {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s.%d", base, n)
		if !taken[candidate] {
			return candidate
		}
	}
}

// waitForChecks polls the checks on a commit until every one has a conclusion
// or the wait is over. Green means every check passed, or no check exists.
func (r *Reconciler) waitForChecks(ctx context.Context, sha string) (bool, error) {
	timeout := r.cfg.CheckTimeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	deadline := r.now().Add(timeout)
	announced := false
	for {
		checks, err := r.api.Checks(ctx, r.cfg.Owner, r.cfg.Repo, sha)
		if err != nil {
			return false, err
		}

		// 1. the named check must exist: GitHub creates the check run a few seconds
		//    after the pull request opens, and no check at all is not green
		if !announced {
			logf("validate: pending")
			announced = true
		}
		pending := false
		found := false
		for _, c := range checks {
			if c.Name == requiredCheck {
				found = true
			}
			switch c.Conclusion {
			case "":
				pending = true
			case "success", "neutral", "skipped":
			default:
				return false, nil
			}
		}
		if found && !pending {
			return true, nil
		}

		// 2. wait, bounded
		if r.now().After(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
}

// requiredCheck is the check a pull request on the backlog must pass before the line manager merges it.
const requiredCheck = "validate"

// settleIssues closes the issue of every entry that became fixed or not
// remediable this pass, and reopens the ones whose declaration was withdrawn.
func (r *Reconciler) settleIssues(ctx context.Context, p *pass, issues []status.Issue) error {
	cards := map[string]status.Issue{}
	for _, is := range issues {
		cards[is.CVE] = is
	}
	done := map[int]bool{}
	for _, rec := range p.records {
		for _, e := range rec.Entries {
			was := p.before[entryKey(rec.Line, e.CVE, e.Library)]
			card, onBoard := cards[e.CVE]
			if !onBoard || card.Number == 0 || done[card.Number] {
				continue
			}
			comment := ""
			reopen := false
			switch {
			case e.Status == book.EntryFixed && was != book.EntryFixed:
				comment = "Fixed by " + e.FixedBy + ", in " + consumeWords(rec.Consume) + "."
			case e.Status == book.EntryNotRemediable && was != book.EntryNotRemediable:
				comment = "Not remediable, stated by " + producerWords(e.Producer) + " on " + p.asOf + ". The entry is counted apart."
			case was == book.EntryNotRemediable && e.Status != book.EntryNotRemediable && e.Status != book.EntryFixed && card.State == "CLOSED":
				comment = "The not remediable label was removed, the entry is " + e.Status + " again."
				reopen = true
			default:
				continue
			}
			done[card.Number] = true
			if r.cfg.Dry || r.api == nil {
				logf("dry run, would %s issue #%d in %s: %s", verb(reopen), card.Number, card.Repository, comment)
				continue
			}
			var err error
			if reopen {
				err = r.api.ReopenIssue(ctx, r.cfg.Owner, card.Repository, card.Number, comment)
			} else {
				err = r.api.CloseIssue(ctx, r.cfg.Owner, card.Repository, card.Number, comment)
			}
			if err != nil {
				return err
			}
			Lowf("%sd issue #%d in %s", verb(reopen), card.Number, card.Repository)
			highf("comment on #%d: %s", card.Number, comment)
		}
	}
	return nil
}

func verb(reopen bool) string {
	if reopen {
		return "reopen"
	}
	return "close"
}

// consumeWords names the BOM in a closing comment, or says there is none yet.
func consumeWords(consume string) string {
	if consume == "" {
		return "no BOM yet"
	}
	at := strings.LastIndex(consume, "@")
	colon := strings.LastIndex(consume[:at], ":")
	return consume[colon+1:at] + " " + consume[at+1:]
}

func producerWords(producer string) string {
	if producer == "" {
		return "the producer on the issue"
	}
	return producer
}
