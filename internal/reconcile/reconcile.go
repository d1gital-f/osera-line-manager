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
	// LocalDir, when set, holds cve-backlog.json and supported-lines.csv and replaces the GitHub read.
	LocalDir string
	// LocalVersion is the book version recorded on a local run, the directory name when empty.
	LocalVersion string
}

// Once runs one pass and returns the records written.
func Once(ctx context.Context, cfg Config) ([]status.Record, error) {
	// 1. the book: at its latest tag on GitHub, or from a local directory for experiments
	var b *book.Book
	var lines []book.Line
	tag, commit := "", ""
	var err error
	var coords []book.Coordinate
	if cfg.LocalDir != "" {
		tag = cfg.LocalVersion
		if tag == "" {
			tag = "local " + filepath.Base(cfg.LocalDir)
		}
		commit = "no commit, read from disk"
		b, err = book.Read(filepath.Join(cfg.LocalDir, "cve-backlog.json"))
		if err != nil {
			return nil, err
		}
		lines, err = book.ReadLines(filepath.Join(cfg.LocalDir, "supported-lines.csv"))
		if err != nil {
			return nil, err
		}
		if _, statErr := os.Stat(filepath.Join(cfg.LocalDir, "coordinates.csv")); statErr == nil {
			coords, err = book.ReadCoordinates(filepath.Join(cfg.LocalDir, "coordinates.csv"))
			if err != nil {
				return nil, err
			}
		}
	} else {
		src := source.New(cfg.Owner, cfg.BacklogRepo, cfg.GitHubToken)
		tag, commit, err = src.LatestTag(ctx)
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
		b, lines, err = parse(rawBook, rawLines)
		if err != nil {
			return nil, err
		}
		// the line's coordinates, when the repository publishes them
		if rawCoords, coordErr := src.File(ctx, tag, "coordinates.csv"); coordErr == nil {
			coords, err = parseCoordinates(rawCoords)
			if err != nil {
				return nil, err
			}
		}
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
			adv, err = osv.Known(ctx, book.EntriesForLine(b, coords, ln.ID))
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
		log.Printf("line %s: %s", rec.Line, rec.Status)
		log.Printf("  book: %s (%s)", tag, shortCommit(commit))
		log.Printf("  in scope %d, fixed %d, in progress %d, open %d, not remediable %d", rec.InScope, len(rec.Fixed), len(rec.InProgress), len(rec.Open), len(rec.NotRemediable))
		log.Printf("  new since book %d, outside the book %d", len(rec.NewSinceBook), len(rec.OutsideBook))
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

func parseCoordinates(raw []byte) ([]book.Coordinate, error) {
	dir, err := os.MkdirTemp("", "line-manager")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "coordinates.csv")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	return book.ReadCoordinates(path)
}

func shortCommit(c string) string {
	if len(c) == 40 {
		return c[:7]
	}
	return c
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
