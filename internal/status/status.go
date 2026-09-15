// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package status computes the state of one supported line from facts the line
// manager does not own: the backlog (what is in scope and what the file
// remembers), the release repository (what the gate promoted, with the evidence
// next to each jar), and the board (where each CVE's issue lives, whether a
// producer labelled it not remediable). Pure: no I/O, same inputs, same answer.
// The release repository is the fact, the backlog file is the memory: an entry
// the file calls fixed stays fixed only while its coordinate is still there.
package status

import (
	"sort"
	"strconv"
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
)

// The three words a line can carry. Fixed only when nothing is open and nothing
// is in progress; not fixed when no entry is fixed; in progress otherwise.
const (
	NotFixed   = "not fixed"
	InProgress = "in progress"
	Fixed      = "fixed"
)

// Issue is what the line manager knows about a CVE's GitHub issue, from the
// board: where it lives, its number there, whether it is open, and whether the
// producer labelled it not remediable. An issue moved out of the backlog
// repository means a producer took it.
type Issue struct {
	CVE        string `json:"cve"`
	Repository string `json:"repository"`
	// Number is the issue number in that repository.
	Number int `json:"number,omitempty"`
	// State is OPEN or CLOSED as GitHub says it.
	State string `json:"state,omitempty"`
	// NotRemediable is true when the issue carries the "not remediable" label.
	NotRemediable bool `json:"not_remediable,omitempty"`
	// ItemID and Lane are the card on the board: its id, and its Status as named there.
	ItemID string `json:"-"`
	Lane   string `json:"-"`
}

// ReasonOnIssue is the reason recorded when a producer labelled the issue not
// remediable: the words are in their comment on the issue, not here.
const ReasonOnIssue = "stated on the issue"

// Promotion is one coordinate the gate promoted, with the evidence file the
// gate published next to it. Evidence is nil when the repository holds none,
// in which case the coordinate fixes nothing.
type Promotion struct {
	Coordinate releases.Coordinate
	Evidence   *releases.Evidence
}

// Inputs is everything the computation reads.
type Inputs struct {
	Line        book.Line
	BookVersion string
	AsOf        string
	// Book is the backlog as the file has it, statuses included.
	Book *book.Book
	// Promoted is what the release repository holds, every coordinate.
	Promoted []Promotion
	// Issues are the board's cards, one per CVE.
	Issues []Issue
	// BacklogRepository is the repository issues are born in; an issue elsewhere is in progress.
	BacklogRepository string
	// Consume is the OSERA BOM of the line as published, group:artifact@version, empty before the first one.
	Consume string
}

// EntryRef names one entry: one CVE on one library.
type EntryRef struct {
	CVE     string `json:"cve"`
	Library string `json:"library"`
}

// FixedEntry is one entry the gate has promoted a fix for.
type FixedEntry struct {
	CVE     string `json:"cve"`
	Library string `json:"library"`
	// Coordinate is the promoted artifact, group:artifact@version.
	Coordinate string `json:"coordinate"`
	// Patch is the REL-003 patch number of that coordinate.
	Patch string `json:"patch"`
	// At is when the line manager first saw the promotion, RFC 3339 UTC.
	At string `json:"at"`
}

// NotRemediable is one entry a producer declared cannot be fixed on the line.
type NotRemediable struct {
	CVE      string `json:"cve"`
	Library  string `json:"library"`
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
	Fixed         []FixedEntry    `json:"fixed"`
	InProgress    []EntryRef      `json:"in_progress"`
	Open          []EntryRef      `json:"open"`
	NotRemediable []NotRemediable `json:"not_remediable"`
	// Discrepancies are things that do not add up, for a person to look at.
	Discrepancies []string `json:"discrepancies"`
	// Consume is what a bank imports today, the OSERA BOM of the line as group:artifact@version.
	// Empty until the first promotion.
	Consume string `json:"consume"`
	// Entries are the backlog's entries for the line with their status as computed,
	// what the caller writes back to cve-backlog.json.
	Entries []book.Entry `json:"-"`
}

// Compute derives the record. Nine steps, no I/O.
func Compute(in Inputs) Record {
	rec := Record{
		Line:          in.Line.ID,
		BookVersion:   in.BookVersion,
		AsOf:          in.AsOf,
		Consume:       in.Consume,
		Fixed:         []FixedEntry{},
		InProgress:    []EntryRef{},
		Open:          []EntryRef{},
		NotRemediable: []NotRemediable{},
		Discrepancies: []string{},
	}

	// 1. in scope: every entry of the backlog on this line, one per CVE and library
	entries := in.Book.ForLine(in.Line.ID)
	rec.InScope = len(entries)

	// 2. the promotions that can fix something: patched coordinates with evidence,
	//    indexed by library and base version
	byLibrary := map[string][]Promotion{}
	for _, p := range in.Promoted {
		if !p.Coordinate.Patched() {
			continue
		}
		if p.Evidence == nil {
			continue
		}
		key := libraryKey(p.Coordinate.Group+":"+p.Coordinate.Artifact, p.Coordinate.Base)
		byLibrary[key] = append(byLibrary[key], p)
	}

	// 3. the board, one card per CVE
	cards := map[string]Issue{}
	for _, is := range in.Issues {
		cards[is.CVE] = is
	}

	// 4. one entry at a time: fixed, else not remediable, else in progress, else open
	for i := range entries {
		e := &entries[i]
		card, onBoard := cards[e.CVE]
		fix, found := bestFix(byLibrary[libraryKey(e.Library, e.Version)], e.CVE)
		switch {
		case found:
			fixEntry(e, fix, in.AsOf)
			rec.Fixed = append(rec.Fixed, FixedEntry{CVE: e.CVE, Library: e.Library, Coordinate: e.FixedBy, Patch: fix.Coordinate.Patch, At: e.FixedAt})
		case declaredNotRemediable(e, card, onBoard):
			declareEntry(e)
			rec.NotRemediable = append(rec.NotRemediable, NotRemediable{CVE: e.CVE, Library: e.Library, Reason: e.Reason, Producer: e.Producer, At: in.AsOf})
		case onBoard && card.Repository != "" && card.Repository != in.BacklogRepository:
			progressEntry(e, card.Repository)
			rec.InProgress = append(rec.InProgress, EntryRef{CVE: e.CVE, Library: e.Library})
		default:
			openEntry(e)
			rec.Open = append(rec.Open, EntryRef{CVE: e.CVE, Library: e.Library})
		}

		// 5. an issue closed while the entry is not done is for a person
		if onBoard && card.State == "CLOSED" && (e.Status == book.EntryOpen || e.Status == book.EntryInProgress) {
			rec.Discrepancies = append(rec.Discrepancies, "issue #"+strconv.Itoa(card.Number)+" for "+e.CVE+" is closed in "+card.Repository+" while the entry on "+e.Library+" is "+e.Status)
		}
	}

	// 6. promotions that do not add up: a patched coordinate of a library on this
	//    line at another base version, and a CVE the evidence names that the backlog
	//    has no entry for on that library
	rec.Discrepancies = append(rec.Discrepancies, promotionDiscrepancies(entries, in.Promoted)...)

	// 7. the lists, in a stable order
	sort.Slice(entries, func(i, j int) bool {
		return entryLess(entries[i].CVE, entries[i].Library, entries[j].CVE, entries[j].Library)
	})
	sort.Slice(rec.Fixed, func(i, j int) bool {
		return entryLess(rec.Fixed[i].CVE, rec.Fixed[i].Library, rec.Fixed[j].CVE, rec.Fixed[j].Library)
	})
	sort.Slice(rec.NotRemediable, func(i, j int) bool {
		return entryLess(rec.NotRemediable[i].CVE, rec.NotRemediable[i].Library, rec.NotRemediable[j].CVE, rec.NotRemediable[j].Library)
	})
	sort.Slice(rec.InProgress, func(i, j int) bool {
		return entryLess(rec.InProgress[i].CVE, rec.InProgress[i].Library, rec.InProgress[j].CVE, rec.InProgress[j].Library)
	})
	sort.Slice(rec.Open, func(i, j int) bool {
		return entryLess(rec.Open[i].CVE, rec.Open[i].Library, rec.Open[j].CVE, rec.Open[j].Library)
	})
	sort.Strings(rec.Discrepancies)

	// 8. the entries as the backlog file will carry them
	rec.Entries = entries

	// 9. the word: fixed only when nothing is open and nothing in progress;
	//    not fixed when no entry is fixed; in progress otherwise
	rec.Status = word(rec)
	return rec
}

// libraryKey joins a library and a base version, the key a promotion is matched on.
func libraryKey(library, base string) string {
	return library + "@" + base
}

// bestFix picks, among the promotions of one library at one base version, the
// one whose evidence names the CVE, the highest patch number when several do.
func bestFix(candidates []Promotion, cve string) (Promotion, bool) {
	var best Promotion
	found := false
	for _, p := range candidates {
		if !names(p.Evidence, cve) {
			continue
		}
		if !found || patchLess(best.Coordinate.Patch, p.Coordinate.Patch) {
			best = p
			found = true
		}
	}
	return best, found
}

// names says whether the evidence lists the CVE under fixes.
func names(ev *releases.Evidence, cve string) bool {
	for _, f := range ev.Fixes {
		if f.CVE == cve {
			return true
		}
	}
	return false
}

// patchLess orders patch numbers numerically, 001 before 002 before 010.
func patchLess(a, b string) bool {
	ai, aErr := strconv.Atoi(a)
	bi, bErr := strconv.Atoi(b)
	if aErr == nil && bErr == nil {
		return ai < bi
	}
	return a < b
}

// fixEntry marks an entry fixed by a promotion. The time is kept when the same
// coordinate already fixed it, so the file does not churn on every pass.
func fixEntry(e *book.Entry, fix Promotion, asOf string) {
	coordinate := fix.Coordinate.String()
	if e.Status != book.EntryFixed || e.FixedBy != coordinate || e.FixedAt == "" {
		e.FixedAt = asOf
	}
	e.Status = book.EntryFixed
	e.FixedBy = coordinate
	e.Repository = ""
	e.Producer = ""
	e.Reason = ""
}

// declaredNotRemediable says whether the entry is not remediable: the label on
// its card says so, or the file says so and the board has no card to say
// otherwise (the issues are not opened yet). A card without the label reopens it.
func declaredNotRemediable(e *book.Entry, card Issue, onBoard bool) bool {
	if onBoard {
		return card.NotRemediable
	}
	return e.Status == book.EntryNotRemediable
}

// declareEntry marks an entry not remediable, keeping the producer and the
// reason the file already carries.
func declareEntry(e *book.Entry) {
	if e.Reason == "" {
		e.Reason = ReasonOnIssue
	}
	e.Status = book.EntryNotRemediable
	e.Repository = ""
	e.FixedBy = ""
	e.FixedAt = ""
}

// progressEntry marks an entry in progress in a patch repository.
func progressEntry(e *book.Entry, repository string) {
	e.Status = book.EntryInProgress
	e.Repository = repository
	e.FixedBy = ""
	e.FixedAt = ""
	e.Producer = ""
	e.Reason = ""
}

// openEntry marks an entry open, nothing else known about it.
func openEntry(e *book.Entry) {
	e.Status = book.EntryOpen
	e.Repository = ""
	e.FixedBy = ""
	e.FixedAt = ""
	e.Producer = ""
	e.Reason = ""
}

// promotionDiscrepancies lists what the release repository holds that the
// backlog cannot place: a patched coordinate of a library on this line at
// another base version, a promoted coordinate with no evidence next to it, and
// a CVE the evidence names that the backlog has no entry for on that library.
// Coordinates of libraries not on this line belong to other lines and are not
// looked at.
func promotionDiscrepancies(entries []book.Entry, promoted []Promotion) []string {
	// 1. the libraries on this line, with their versions and CVEs
	versions := map[string]map[string]bool{}
	cves := map[string]map[string]bool{}
	for _, e := range entries {
		if versions[e.Library] == nil {
			versions[e.Library] = map[string]bool{}
			cves[e.Library] = map[string]bool{}
		}
		versions[e.Library][e.Version] = true
		cves[e.Library][e.CVE] = true
	}

	// 2. every patched coordinate of one of those libraries
	var out []string
	for _, p := range promoted {
		if !p.Coordinate.Patched() {
			continue
		}
		library := p.Coordinate.Group + ":" + p.Coordinate.Artifact
		if versions[library] == nil {
			continue
		}
		if !versions[library][p.Coordinate.Base] {
			out = append(out, "promoted "+p.Coordinate.String()+" is on base "+p.Coordinate.Base+", the line has "+library+" at "+join(versions[library]))
			continue
		}
		if p.Evidence == nil {
			out = append(out, "promoted "+p.Coordinate.String()+" has no evidence file next to it, it fixes nothing")
			continue
		}
		for _, cve := range p.Evidence.CVEs() {
			if !cves[library][cve] {
				out = append(out, "fixed, not in the backlog: "+cve+" on "+p.Coordinate.String())
			}
		}
	}
	return out
}

// join lists the keys of a set, sorted, comma separated.
func join(set map[string]bool) string {
	var keys []string
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// entryLess orders by CVE, then by library.
func entryLess(aCVE, aLib, bCVE, bLib string) bool {
	if aCVE != bCVE {
		return aCVE < bCVE
	}
	return aLib < bLib
}

// word derives the line's word from the lists of a record.
func word(rec Record) string {
	if len(rec.Open) == 0 && len(rec.InProgress) == 0 {
		return Fixed
	}
	if len(rec.Fixed) == 0 {
		return NotFixed
	}
	return InProgress
}
