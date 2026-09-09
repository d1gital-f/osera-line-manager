// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package book reads the order book and the supported lines as the backlog
// repository publishes them: cve-backlog.json (entry schema 0.5.0) and
// supported-lines.csv. It reads, it never judges.
package book

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
)

// Entry is one row of the book: one CVE on one library on the lines it applies to.
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

// Line is one row of supported-lines.csv.
type Line struct {
	ID               string
	FrameworkVersion string
	BootVersion      string
	SecurityVersion  string
	Status           string
	Source           string
}

// Read loads the book from a file and checks the schema it claims.
func Read(path string) (*Book, error) {
	// 1. the file
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the book: %w", err)
	}

	// 2. the shape
	var b Book
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parsing the book: %w", err)
	}

	// 3. the schema this reader understands
	if b.SchemaVersion != "0.5.0" {
		return nil, fmt.Errorf("book schema %q, this reader wants 0.5.0", b.SchemaVersion)
	}
	return &b, nil
}

// ForLine keeps the entries that apply to one line, in book order.
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
	if len(rows) < 2 {
		return nil, fmt.Errorf("the supported lines file has no rows")
	}

	// 3. one Line per row
	var out []Line
	for _, r := range rows[1:] {
		if len(r) < 6 {
			return nil, fmt.Errorf("supported line row %q has %d columns, 6 expected", r, len(r))
		}
		out = append(out, Line{
			ID:               r[0],
			FrameworkVersion: r[1],
			BootVersion:      r[2],
			SecurityVersion:  r[3],
			Status:           r[4],
			Source:           r[5],
		})
	}
	return out, nil
}

// Coordinate is one library at one version on one line, from coordinates.csv: the
// line's full dependency list, of which the book is the subset with a qualifying CVE.
type Coordinate struct {
	Line    string
	Library string
	Version string
}

// ReadCoordinates loads coordinates.csv (line_id, library, version).
func ReadCoordinates(path string) ([]Coordinate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading the coordinates: %w", err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing the coordinates: %w", err)
	}
	var out []Coordinate
	for i, r := range rows {
		if i == 0 {
			continue
		}
		if len(r) < 3 {
			return nil, fmt.Errorf("coordinate row %q has %d columns, 3 expected", r, len(r))
		}
		out = append(out, Coordinate{Line: r[0], Library: r[1], Version: r[2]})
	}
	return out, nil
}

// EntriesForLine merges the book's entries and the line's coordinates into one list of
// library and version pairs, each once, so the advisory sources see the whole line.
func EntriesForLine(b *Book, coords []Coordinate, lineID string) []Entry {
	seen := map[string]bool{}
	var out []Entry
	for _, e := range b.ForLine(lineID) {
		key := e.Library + "@" + e.Version
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	for _, c := range coords {
		if c.Line != lineID {
			continue
		}
		key := c.Library + "@" + c.Version
		if !seen[key] {
			seen[key] = true
			out = append(out, Entry{Library: c.Library, Version: c.Version, Lines: []string{lineID}})
		}
	}
	return out
}
