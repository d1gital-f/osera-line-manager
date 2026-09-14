// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// The status columns of supported-lines.csv. The first six columns are the line as
// people declared it; these nine are what the line manager found, rewritten on
// every pass, never edited by hand.
var statusColumns = book.LineColumns[book.DeclaredColumns:]

// WriteLines rewrites supported-lines.csv with the status columns filled from the records.
func WriteLines(path string, records []status.Record) error {
	// 1. the file as it is
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	rows, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("%s is empty", path)
	}

	// 2. the header: the six declared columns, then the status columns
	if len(rows[0]) < book.DeclaredColumns {
		return fmt.Errorf("%s has %d header columns, at least %d expected", path, len(rows[0]), book.DeclaredColumns)
	}
	header := append([]string{}, rows[0][:book.DeclaredColumns]...)
	header = append(header, statusColumns...)

	// 3. one row per line, the declared part kept, the status part from the record
	byLine := map[string]status.Record{}
	for _, r := range records {
		byLine[r.Line] = r
	}
	out := [][]string{header}
	for _, row := range rows[1:] {
		if len(row) < book.DeclaredColumns {
			return fmt.Errorf("%s row %q has %d columns, at least %d expected", path, row[0], len(row), book.DeclaredColumns)
		}
		declared := append([]string{}, row[:book.DeclaredColumns]...)
		rec, found := byLine[row[0]]
		if !found {
			out = append(out, append(declared, make([]string, len(statusColumns))...))
			continue
		}
		out = append(out, append(declared,
			rec.Status,
			rec.BookVersion,
			rec.AsOf,
			fmt.Sprint(rec.InScope),
			fmt.Sprint(len(rec.Fixed)),
			fmt.Sprint(len(rec.InProgress)),
			fmt.Sprint(len(rec.Open)),
			fmt.Sprint(len(rec.NotRemediable)),
			rec.Consume,
		))
	}

	// 4. written back
	w, err := os.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()
	cw := csv.NewWriter(w)
	if err := cw.WriteAll(out); err != nil {
		return err
	}
	return cw.Error()
}
