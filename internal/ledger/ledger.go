// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package ledger reads what the gate recorded: release sets promoted into the
// release repository, retractions, and statements that a CVE cannot be fixed on
// a line. Today it reads a JSON export; the gate's own store comes later, the
// shape stays.
package ledger

import (
	"encoding/json"
	"fmt"
	"os"
)

// Event is one ledger record the line manager cares about.
type Event struct {
	// Type is promoted, retracted or not-remediable.
	Type string `json:"type"`
	// Line is the supported line id the event is about.
	Line string `json:"line"`
	// SetID names the release set (promoted and retracted).
	SetID string `json:"set_id,omitempty"`
	// Coordinates are the artifacts of the set, group:artifact@version.
	Coordinates []string `json:"coordinates,omitempty"`
	// CVEs are the CVEs the set's evidence file says it fixes.
	CVEs []string `json:"cves,omitempty"`
	// CVE is the one CVE a not-remediable statement is about.
	CVE string `json:"cve,omitempty"`
	// Reason is the producer's stated reason a CVE cannot be fixed on the line.
	Reason string `json:"reason,omitempty"`
	// Producer is the approved producer id behind the event.
	Producer string `json:"producer,omitempty"`
	// At is when the gate recorded it, RFC 3339.
	At string `json:"at"`
}

// Ledger is the ordered list of events, oldest first.
type Ledger struct {
	Events []Event `json:"events"`
}

// Read loads a ledger export.
func Read(path string) (*Ledger, error) {
	// 1. the file
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the ledger: %w", err)
	}

	// 2. the shape
	var l Ledger
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("parsing the ledger: %w", err)
	}

	// 3. every event names a type and a line
	for i, e := range l.Events {
		if e.Type != "promoted" && e.Type != "retracted" && e.Type != "not-remediable" {
			return nil, fmt.Errorf("event %d has type %q, expected promoted, retracted or not-remediable", i, e.Type)
		}
		if e.Line == "" {
			return nil, fmt.Errorf("event %d names no line", i)
		}
	}
	return &l, nil
}

// Empty is a ledger with nothing in it, the state before the first promotion.
func Empty() *Ledger {
	return &Ledger{}
}
