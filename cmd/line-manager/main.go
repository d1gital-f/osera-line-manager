// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// line-manager computes the status of a supported line from the book, the
// ledger and the issues, and prints the record. The loop, the pull request and
// the BOM come after this one function is agreed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/ledger"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

func main() {
	// 1. the inputs, all files for now
	bookPath := flag.String("book", "cve-backlog.json", "the order book")
	linesPath := flag.String("lines", "supported-lines.csv", "the supported lines")
	ledgerPath := flag.String("ledger", "", "a ledger export, empty for none")
	lineID := flag.String("line", "", "the line to report on, every supported line when empty")
	bookVersion := flag.String("book-version", "", "the tag the book was published under")
	flag.Parse()

	// 2. read
	b, err := book.Read(*bookPath)
	fail(err)
	lines, err := book.ReadLines(*linesPath)
	fail(err)
	l := ledger.Empty()
	if *ledgerPath != "" {
		l, err = ledger.Read(*ledgerPath)
		fail(err)
	}

	// 3. one record per line asked for
	asOf := time.Now().UTC().Format(time.RFC3339)
	var records []status.Record
	for _, ln := range lines {
		if *lineID != "" && ln.ID != *lineID {
			continue
		}
		rec := status.Compute(status.Inputs{
			Line:              ln.ID,
			BookVersion:       *bookVersion,
			AsOf:              asOf,
			Book:              b,
			Ledger:            l,
			BacklogRepository: "backlog",
		})
		records = append(records, rec)
	}

	// 4. print
	out, err := json.MarshalIndent(records, "", "  ")
	fail(err)
	fmt.Println(string(out))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
