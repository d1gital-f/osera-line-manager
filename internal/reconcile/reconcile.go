// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package reconcile is the loop: read the book at its latest tag, the ledger,
// the issues and the advisories, compute one record per line, write it. Every
// pass starts from nothing and is safe to repeat.
package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/advisories"
	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/issues"
	"github.com/d1gital-f/osera-line-manager/internal/ledger"
	"github.com/d1gital-f/osera-line-manager/internal/source"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Config is what one line manager instance watches.
type Config struct {
	Owner       string
	BacklogRepo string
	LedgerPath  string
	OutDir      string
	GitHubToken string
	QueryOSV    bool
	QueryIssues bool
}

// Once runs one pass and returns the records written.
func Once(ctx context.Context, cfg Config) ([]status.Record, error) {
	// 1. the book at its latest tag
	src := source.New(cfg.Owner, cfg.BacklogRepo, cfg.GitHubToken)
	tag, commit, err := src.LatestTag(ctx)
	if err != nil {
		return nil, err
	}
	rawBook, err := src.File(ctx, tag, "cve-backlog.json")
	if err != nil {
		return nil, err
	}
	rawLines, err := src.File(ctx, tag, "supported-lines.csv")
	if err != nil {
		return nil, err
	}
	b, lines, err := parse(rawBook, rawLines)
	if err != nil {
		return nil, err
	}

	// 2. the ledger, a file until the gate writes one
	l := ledger.Empty()
	if cfg.LedgerPath != "" {
		l, err = ledger.Read(cfg.LedgerPath)
		if err != nil {
			return nil, err
		}
	}

	// 3. the issues, one search
	var is []status.Issue
	if cfg.QueryIssues {
		is, err = issues.New(cfg.Owner, cfg.GitHubToken).Find(ctx, cfg.BacklogRepo)
		if err != nil {
			return nil, err
		}
	}

	// 4. one record per line
	asOf := time.Now().UTC().Format(time.RFC3339)
	var records []status.Record
	for _, ln := range lines {
		var adv []status.Advisory
		if cfg.QueryOSV {
			osv := advisories.New()
			adv, err = osv.Known(ctx, b.ForLine(ln.ID))
			if err != nil {
				return nil, err
			}
			// resolve the ids the book does not know, then compare by CVE again
			adv = notInBook(adv, b.ForLine(ln.ID))
			adv, err = osv.Resolve(ctx, adv, filepath.Join(cfg.OutDir, "osv-cache.json"))
			if err != nil {
				return nil, err
			}
			adv = notInBook(adv, b.ForLine(ln.ID))
		}
		rec := status.Compute(status.Inputs{
			Line:              ln.ID,
			BookVersion:       tag,
			AsOf:              asOf,
			Book:              b,
			Ledger:            l,
			Issues:            is,
			Advisories:        adv,
			BacklogRepository: cfg.BacklogRepo,
			SeveritySource:    "OSV, GitHub advisory severity word (CRITICAL 9, HIGH 7, MODERATE 4, LOW 0.1), NVD CVSS 3.1 to follow",
		})
		records = append(records, rec)

		// 5. written where the feed will pick it up, one file per line
		if cfg.OutDir != "" {
			if err := write(cfg.OutDir, rec); err != nil {
				return nil, err
			}
		}
		log.Printf("line %s: book %s (%s) %s, in scope %d, fixed %d, in progress %d, open %d, not remediable %d, new since book %d, outside the book %d",
			rec.Line, tag, commit[:7], rec.Status, rec.InScope, len(rec.Fixed), len(rec.InProgress), len(rec.Open), len(rec.NotRemediable), len(rec.NewSinceBook), len(rec.OutsideBook))
	}
	return records, nil
}

// Loop runs Once now and then every interval until the context ends.
func Loop(ctx context.Context, cfg Config, interval time.Duration) {
	for {
		if _, err := Once(ctx, cfg); err != nil {
			log.Printf("reconcile: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func parse(rawBook, rawLines []byte) (*book.Book, []book.Line, error) {
	dir, err := os.MkdirTemp("", "line-manager")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	bookPath := filepath.Join(dir, "cve-backlog.json")
	linesPath := filepath.Join(dir, "supported-lines.csv")
	if err := os.WriteFile(bookPath, rawBook, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(linesPath, rawLines, 0o600); err != nil {
		return nil, nil, err
	}
	b, err := book.Read(bookPath)
	if err != nil {
		return nil, nil, err
	}
	lines, err := book.ReadLines(linesPath)
	if err != nil {
		return nil, nil, err
	}
	return b, lines, nil
}

// notInBook keeps the advisories whose CVE is not an entry of the line.
func notInBook(advs []status.Advisory, entries []book.Entry) []status.Advisory {
	known := map[string]bool{}
	for _, e := range entries {
		known[e.CVE] = true
	}
	var out []status.Advisory
	for _, a := range advs {
		if !known[a.CVE] {
			out = append(out, a)
		}
	}
	return out
}

func write(dir string, rec status.Record) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.json", rec.Line))
	return os.WriteFile(path, out, 0o644)
}
