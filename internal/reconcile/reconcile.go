// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package reconcile is the loop: read the backlog at its latest tag, the ledger
// and the board, compute one record per line, write it. Every pass starts from
// nothing and is safe to repeat. The scan and the graph are wired in later.
package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/board"
	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/ledger"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Config is what one line manager instance watches.
type Config struct {
	Owner       string
	BacklogRepo string
	LedgerPath  string
	OutDir      string
	GitHubToken string
	// Scan says whether the advisory sources are read; not wired yet, the scan package is.
	Scan bool
	// QueryBoard reads the organisation board, BoardNumber is the project number.
	QueryBoard  bool
	BoardNumber int
	// LocalDir, when set, holds cve-backlog.json and supported-lines.csv and replaces the GitHub read.
	LocalDir string
	// LocalVersion is the book version recorded on a local run, the directory name when empty.
	LocalVersion string
	// LinesPath, when set, is a supported-lines.csv rewritten with the status columns after every pass.
	LinesPath string
}

// Once runs one pass and returns the records written.
func Once(ctx context.Context, cfg Config) ([]status.Record, error) {
	// 1. the book and the lines, from a local directory until the clone is wired in
	var b *book.Book
	var lines []book.Line
	tag, commit := "", ""
	var err error
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
	} else {
		return nil, fmt.Errorf("a local directory is required until the clone is wired in (--local)")
	}

	// 2. the ledger, a file until the gate writes one
	l := ledger.Empty()
	if cfg.LedgerPath != "" {
		l, err = ledger.Read(cfg.LedgerPath)
		if err != nil {
			return nil, err
		}
	}

	// 3. the issues, from the board, one paged query
	var is []status.Issue
	if cfg.QueryBoard {
		cards, err := board.New(cfg.Owner, cfg.BoardNumber, cfg.GitHubToken).Read(ctx)
		if err != nil {
			return nil, err
		}
		is = board.Issues(cards, cfg.BacklogRepo)
	}

	// 4. one record per line
	asOf := time.Now().UTC().Format(time.RFC3339)
	var records []status.Record
	for _, ln := range lines {
		var adv []status.Advisory
		rec := status.Compute(status.Inputs{
			Line:              ln.ID,
			BookVersion:       tag,
			AsOf:              asOf,
			Book:              b,
			Ledger:            l,
			Issues:            is,
			Advisories:        adv,
			BacklogRepository: cfg.BacklogRepo,
			Consume:           ln.Consume,
			SeveritySource:    "NVD CVSS 3.1 base score as recorded at NVD; GitHub's advisory word (CRITICAL 9, HIGH 7, MODERATE 4, LOW 0.1) only where NVD has no score yet",
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
	// 6. the status columns of supported-lines.csv, when asked to write them
	if cfg.LinesPath != "" {
		if err := WriteLines(cfg.LinesPath, records); err != nil {
			return nil, err
		}
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
