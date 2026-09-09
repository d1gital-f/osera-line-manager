// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package status computes the state of one supported line from facts the line
// manager does not own: the book (what is in scope), the ledger (what the gate
// promoted or retracted, and what a producer declared not remediable), the
// issues (what a producer is working on) and the advisories (what is known that
// the book does not carry yet). Pure: no I/O, same inputs, same answer.
package status

import (
	"sort"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/ledger"
)

// The two words a line can carry. There is no third: a line with a CVE the book
// does not know yet is partially remediated, and the record says why.
const (
	Remediated          = "remediated"
	PartiallyRemediated = "partially remediated"
)

// Issue is what the line manager knows about a CVE's GitHub issue: where it
// lives. An issue moved out of the backlog repository means a producer took it.
type Issue struct {
	CVE        string
	Repository string
}

// Advisory is one CVE seen in the advisory sources for a coordinate on the line.
type Advisory struct {
	CVE     string
	Library string
	Version string
}

// Inputs is everything the computation reads.
type Inputs struct {
	Line        string
	BookVersion string
	AsOf        string
	Book        *book.Book
	Ledger      *ledger.Ledger
	Issues      []Issue
	Advisories  []Advisory
	// BacklogRepository is the repository issues are born in; an issue elsewhere is in progress.
	BacklogRepository string
}

// Fixed is one CVE the gate has promoted a fix for.
type Fixed struct {
	CVE         string   `json:"cve"`
	Coordinates []string `json:"coordinates"`
	SetID       string   `json:"set_id"`
	At          string   `json:"at"`
}

// NotRemediable is one CVE a producer declared cannot be fixed on the line.
type NotRemediable struct {
	CVE      string `json:"cve"`
	Reason   string `json:"reason"`
	Producer string `json:"producer"`
	At       string `json:"at"`
}

// Record is the line status: what a bank reads.
type Record struct {
	Line          string          `json:"line"`
	BookVersion   string          `json:"book_version"`
	AsOf          string          `json:"as_of"`
	Status        string          `json:"status"`
	InScope       int             `json:"in_scope"`
	Fixed         []Fixed         `json:"fixed"`
	InProgress    []string        `json:"in_progress"`
	Open          []string        `json:"open"`
	NotRemediable []NotRemediable `json:"not_remediable"`
	NewSinceBook  []Advisory      `json:"new_since_book"`
}

// Compute derives the record. Nine steps, no I/O.
func Compute(in Inputs) Record {
	rec := Record{Line: in.Line, BookVersion: in.BookVersion, AsOf: in.AsOf}

	// 1. the CVEs in scope: every entry of the book on this line, one CVE once
	inScope := map[string]bool{}
	for _, e := range in.Book.ForLine(in.Line) {
		inScope[e.CVE] = true
	}
	rec.InScope = len(inScope)

	// 2. replay the ledger for this line, oldest first: a promotion fixes its CVEs,
	//    a retraction of the same set unfixes them, a statement marks a CVE not remediable
	fixed := map[string]Fixed{}
	promotedSets := map[string]ledger.Event{}
	notRemediable := map[string]NotRemediable{}
	for _, ev := range in.Ledger.Events {
		if ev.Line != in.Line {
			continue
		}
		switch ev.Type {
		case "promoted":
			promotedSets[ev.SetID] = ev
			for _, cve := range ev.CVEs {
				fixed[cve] = Fixed{CVE: cve, Coordinates: ev.Coordinates, SetID: ev.SetID, At: ev.At}
			}
		case "retracted":
			set, known := promotedSets[ev.SetID]
			if !known {
				continue
			}
			delete(promotedSets, ev.SetID)
			for _, cve := range set.CVEs {
				if fixed[cve].SetID == ev.SetID {
					delete(fixed, cve)
				}
			}
		case "not-remediable":
			notRemediable[ev.CVE] = NotRemediable{CVE: ev.CVE, Reason: ev.Reason, Producer: ev.Producer, At: ev.At}
		}
	}

	// 3. a fix or a statement only counts for a CVE the book has in scope
	for cve := range fixed {
		if !inScope[cve] {
			delete(fixed, cve)
		}
	}
	for cve := range notRemediable {
		if !inScope[cve] {
			delete(notRemediable, cve)
		}
	}

	// 4. a fixed CVE is fixed, whatever a producer said before
	for cve := range fixed {
		delete(notRemediable, cve)
	}

	// 5. in progress: an issue that left the backlog repository, for a CVE not yet fixed
	inProgress := map[string]bool{}
	for _, is := range in.Issues {
		if !inScope[is.CVE] {
			continue
		}
		if _, done := fixed[is.CVE]; done {
			continue
		}
		if _, declared := notRemediable[is.CVE]; declared {
			continue
		}
		if is.Repository != "" && is.Repository != in.BacklogRepository {
			inProgress[is.CVE] = true
		}
	}

	// 6. open: in scope, not fixed, not declared, not in progress
	for cve := range inScope {
		if _, done := fixed[cve]; done {
			continue
		}
		if _, declared := notRemediable[cve]; declared {
			continue
		}
		if inProgress[cve] {
			continue
		}
		rec.Open = append(rec.Open, cve)
	}

	// 7. new since the book: an advisory on the line the book does not carry
	seen := map[string]bool{}
	for _, a := range in.Advisories {
		if inScope[a.CVE] || seen[a.CVE] {
			continue
		}
		seen[a.CVE] = true
		rec.NewSinceBook = append(rec.NewSinceBook, a)
	}

	// 8. the lists, in a stable order
	for _, f := range fixed {
		rec.Fixed = append(rec.Fixed, f)
	}
	for _, n := range notRemediable {
		rec.NotRemediable = append(rec.NotRemediable, n)
	}
	for cve := range inProgress {
		rec.InProgress = append(rec.InProgress, cve)
	}
	sort.Slice(rec.Fixed, func(i, j int) bool { return rec.Fixed[i].CVE < rec.Fixed[j].CVE })
	sort.Slice(rec.NotRemediable, func(i, j int) bool { return rec.NotRemediable[i].CVE < rec.NotRemediable[j].CVE })
	sort.Strings(rec.InProgress)
	sort.Strings(rec.Open)
	sort.Slice(rec.NewSinceBook, func(i, j int) bool { return rec.NewSinceBook[i].CVE < rec.NewSinceBook[j].CVE })

	// 9. the word: remediated only when nothing is open, nothing in progress and nothing new
	if len(rec.Open) == 0 && len(rec.InProgress) == 0 && len(rec.NewSinceBook) == 0 {
		rec.Status = Remediated
	} else {
		rec.Status = PartiallyRemediated
	}
	return rec
}
