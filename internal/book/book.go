// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package book reads the backlog and the supported lines as the backlog
// repository publishes them: cve-backlog.json (entry schema 0.6.0) and
// supported-lines.csv (fifteen columns). It reads, it never judges.
package book

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SchemaVersion is the schema this reader understands.
const SchemaVersion = "0.6.0"

// The four states of an entry, written by the line manager and by nobody else.
const (
	EntryOpen          = "open"
	EntryInProgress    = "in progress"
	EntryFixed         = "fixed"
	EntryNotRemediable = "not remediable"
)

// Entry is one row of the backlog: one CVE on one library on one line, with the
// reason it is there and the state the line manager found it in.
type Entry struct {
	CVE            string   `json:"cve"`
	Library        string   `json:"library"`
	Version        string   `json:"version"`
	Lines          []string `json:"lines"`
	CVSS           float64  `json:"cvss"`
	CVSSVersion    string   `json:"cvss_version"`
	CISAKEV        bool     `json:"cisa_kev"`
	EPSSPercentile *float64 `json:"epss_percentile"`
	Priority       string   `json:"priority"`
	Why            []string `json:"why"`
	Summary        string   `json:"summary"`
	// Status is open, in progress, fixed or not remediable.
	Status string `json:"status"`
	// Repository is the patch repository the issue moved to (in progress), owner/name.
	Repository string `json:"repository,omitempty"`
	// FixedBy is the promoted coordinate, group:artifact@version (fixed).
	FixedBy string `json:"fixed_by,omitempty"`
	// FixedAt is when the line manager saw the promotion, RFC 3339 UTC (fixed).
	FixedAt string `json:"fixed_at,omitempty"`
	// Producer is the producer id from the approved producers file (not remediable).
	Producer string `json:"producer,omitempty"`
	// Reason is the reason the producer gave on the issue (not remediable).
	Reason string `json:"reason,omitempty"`
}

// Book is the file as published, the entries in priority order.
type Book struct {
	SchemaVersion string  `json:"schema_version"`
	Title         string  `json:"title"`
	StandardsPack string  `json:"standards_pack"`
	Generated     string  `json:"generated"`
	EntrySchema   string  `json:"entry_schema"`
	Entries       []Entry `json:"entries"`
}

// LineColumns are the columns of supported-lines.csv, in order: six declared
// by people, nine written by the line manager.
var LineColumns = []string{
	"line_id", "ecosystem", "anchor", "components", "scope", "source",
	"status", "book_version", "as_of", "in_scope", "fixed", "in_progress", "open", "not_remediable", "consume",
}

// DeclaredColumns is how many columns people write; the rest are the line manager's.
const DeclaredColumns = 6

// Line is one row of supported-lines.csv.
type Line struct {
	// The six declared columns.
	ID         string
	Ecosystem  string
	Anchor     string
	Components []string
	Scope      string
	Source     string
	// The nine status columns, as written, empty until the line manager writes them.
	Status        string
	BookVersion   string
	AsOf          string
	InScope       string
	Fixed         string
	InProgress    string
	Open          string
	NotRemediable string
	Consume       string
}

// Read loads the backlog from a file and checks the schema it claims.
func Read(path string) (*Book, error) {
	// 1. the file
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the backlog: %w", err)
	}

	// 2. the shape
	var b Book
	err = json.Unmarshal(raw, &b)
	if err != nil {
		return nil, fmt.Errorf("parsing the backlog: %w", err)
	}

	// 3. the schema this reader understands
	if b.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("backlog schema %q, this reader wants %s", b.SchemaVersion, SchemaVersion)
	}

	// 4. every entry carries a known status
	for i, e := range b.Entries {
		if !knownStatus(e.Status) {
			return nil, fmt.Errorf("entry %d (%s on %s) has status %q, expected open, in progress, fixed or not remediable", i, e.CVE, e.Library, e.Status)
		}
	}
	return &b, nil
}

// knownStatus says whether a word is one of the four states.
func knownStatus(s string) bool {
	switch s {
	case EntryOpen, EntryInProgress, EntryFixed, EntryNotRemediable:
		return true
	}
	return false
}

// ForLine keeps the entries that apply to one line, in backlog order.
func (b *Book) ForLine(lineID string) []Entry {
	var out []Entry
	for _, e := range b.Entries {
		for _, l := range e.Lines {
			if l == lineID {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ReadLines loads supported-lines.csv.
func ReadLines(path string) ([]Line, error) {
	// 1. the file
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading the supported lines: %w", err)
	}
	defer f.Close()

	// 2. the rows, header first
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing the supported lines: %w", err)
	}
	if len(rows) < 1 {
		return nil, fmt.Errorf("the supported lines file has no header")
	}

	// 3. the header names the fifteen columns, in order
	err = checkHeader(rows[0])
	if err != nil {
		return nil, err
	}

	// 4. one Line per row
	var out []Line
	for _, r := range rows[1:] {
		if len(r) != len(LineColumns) {
			return nil, fmt.Errorf("supported line row %q has %d columns, %d expected", r[0], len(r), len(LineColumns))
		}
		out = append(out, Line{
			ID:            r[0],
			Ecosystem:     r[1],
			Anchor:        r[2],
			Components:    strings.Fields(r[3]),
			Scope:         r[4],
			Source:        r[5],
			Status:        r[6],
			BookVersion:   r[7],
			AsOf:          r[8],
			InScope:       r[9],
			Fixed:         r[10],
			InProgress:    r[11],
			Open:          r[12],
			NotRemediable: r[13],
			Consume:       r[14],
		})
	}
	return out, nil
}

// checkHeader compares the header row with the fifteen column names.
func checkHeader(header []string) error {
	if len(header) != len(LineColumns) {
		return fmt.Errorf("the supported lines header has %d columns, %d expected", len(header), len(LineColumns))
	}
	for i, name := range LineColumns {
		if header[i] != name {
			return fmt.Errorf("supported lines column %d is %q, expected %q", i+1, header[i], name)
		}
	}
	return nil
}
