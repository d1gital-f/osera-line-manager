// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// The one logger. Every line is the full timestamp in RFC 3339 UTC, a space,
// then a sentence that states a fact. Three levels, chosen at start:
//
//	low     the pass start and end, the per line summary, every write to GitHub
//	        or Nexus, every error and discrepancy
//	medium  low plus one line per step of the pass
//	high    medium plus the detail of each step: every Maven run, every
//	        evidence file, every staged file, every comment, the Grype database
//
// Other packages never log on their own: they get a function from here.

// Level is how much the log says.
type Level int

const (
	Low Level = iota
	Medium
	High
)

// ParseLevel reads low, medium or high.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return Low, nil
	case "medium", "":
		return Medium, nil
	case "high":
		return High, nil
	}
	return Medium, fmt.Errorf("log level %q, expected low, medium or high", s)
}

func (l Level) String() string {
	switch l {
	case Low:
		return "low"
	case High:
		return "high"
	}
	return "medium"
}

var (
	logMu    sync.Mutex
	logLevel           = Medium
	logOut   io.Writer = os.Stderr
	// logClock is the clock the timestamp comes from, replaceable in tests.
	logClock = time.Now
)

// SetLevel picks how much is said from now on.
func SetLevel(l Level) {
	logMu.Lock()
	defer logMu.Unlock()
	logLevel = l
}

// emit writes one line when its level is within the chosen one.
func emit(l Level, format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	if l > logLevel {
		return
	}
	stamp := logClock().UTC().Format(time.RFC3339)
	fmt.Fprintf(logOut, "%s %s\n", stamp, fmt.Sprintf(format, a...))
}

// Lowf says what must always be said: a pass, a write, an error.
func Lowf(format string, a ...any) {
	emit(Low, format, a...)
}

// logf says one line per step, the medium level, the default.
func logf(format string, a ...any) {
	emit(Medium, format, a...)
}

// highf says the detail of a step.
func highf(format string, a ...any) {
	emit(High, format, a...)
}

// seconds renders a duration rounded to the second, "12s" or "1m52s".
func seconds(d time.Duration) string {
	return d.Round(time.Second).String()
}

func init() {
	// the standard logger, should anything still reach it, writes no prefix of its own
	log.SetFlags(0)
}
