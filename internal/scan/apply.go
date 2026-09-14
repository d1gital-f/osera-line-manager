// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/rules"
)

// The words the backlog carries in why, the same the generator wrote
// (4-build-cve-backlog.py): Dov's rule from risk-navigator #7, then the
// signals behind the priority.
var whyRule = map[string]string{
	"critical":      "Rule 1: include all Critical CVEs, CVSS >= 9.0",
	"high":          "Rule 2: include all High CVEs, CVSS >= 7.0",
	"kev":           "Rule 3: include any CVE listed in CISA KEV, regardless of CVSS",
	"medium-signal": "Rule 4: include Medium CVEs, CVSS 6.0 to 6.9, only when at least one additional risk signal exists",
}

var signalWords = map[string]string{
	"kev":     "listed in CISA KEV",
	"epss":    "EPSS percentile at or above 0.90",
	"graph":   "on the curated list and on the runtime path of the line",
	"osv-fix": "a fix exists on the same line per the advisory",
	"member":  "member reported exploit evidence",
}

// The score sources, as words, for the why of an entry.
var sourceWords = map[string]string{
	"nvd":      "CVSS score as scored by NVD",
	"cna":      "CVSS score from the reporting organisation as recorded at NVD",
	"osv-word": "severity word from the advisory database, no numeric score yet",
}

// Excluded is one finding the rules left out, in the backlog's shape plus the reason.
type Excluded struct {
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
	Reason         string   `json:"reason"`
}

// Split is what Apply returns: the entries for the backlog and the excluded list.
type Split struct {
	Entries  []book.Entry
	Excluded []Excluded
}

// Apply puts the rules on every finding of one line. A finding is an entry
// when the rules say applicable and its group is on the curated list; otherwise
// it is excluded, with the reason in words. On the runtime path is true for
// every component: the graph is the line's runtime closure.
func Apply(lineID string, findings []Finding, r *rules.Rules) Split {
	var out Split
	for _, f := range findings {
		// 1. the facts and the rules' word
		onList := r.CuratedList(f.Component.Group)
		facts := rules.Facts{
			Score:          f.Score,
			CVSSSource:     f.CVSSSource,
			KEV:            f.KEV,
			EPSSPercentile: f.EPSSPercentile,
			MemberLevel:    rules.MemberNone,
			OnCuratedList:  onList,
			OnRuntimePath:  true,
			FixedByUpgrade: f.FixedByUpgrade,
		}
		o := r.Evaluate(facts)

		// 2. the fields both lists share
		score := 0.0
		if f.Score != nil {
			score = *f.Score
		}
		why := whyOf(o)

		// 3. in, or out with the reason
		if o.Applicable && onList {
			out.Entries = append(out.Entries, book.Entry{
				CVE:            f.CVE,
				Library:        f.Component.Name(),
				Version:        f.Component.Version,
				Lines:          []string{lineID},
				CVSS:           score,
				CVSSVersion:    "3.1",
				CISAKEV:        f.KEV,
				EPSSPercentile: f.EPSSPercentile,
				Priority:       o.Priority,
				Why:            why,
				Summary:        f.Summary,
				Status:         book.EntryOpen,
			})
			continue
		}
		out.Excluded = append(out.Excluded, Excluded{
			CVE:            f.CVE,
			Library:        f.Component.Name(),
			Version:        f.Component.Version,
			Lines:          []string{lineID},
			CVSS:           score,
			CVSSVersion:    "3.1",
			CISAKEV:        f.KEV,
			EPSSPercentile: f.EPSSPercentile,
			Priority:       o.Priority,
			Why:            why,
			Summary:        f.Summary,
			Reason:         reasonOf(f, o, onList, r),
		})
	}
	sortEntries(out.Entries)
	sortExcluded(out.Excluded)
	return out
}

// whyOf writes the rule that put the CVE in, then the signals behind the priority.
func whyOf(o rules.Outcome) []string {
	why := []string{}
	if rule, known := whyRule[o.Rule]; known {
		why = append(why, rule)
	}
	for _, in := range o.Inputs {
		if word, known := signalWords[in]; known {
			why = append(why, word)
			continue
		}
		if word, known := sourceWords[in]; known {
			why = append(why, word)
		}
	}
	return why
}

// reasonOf says, in words, why a finding is not in the backlog.
func reasonOf(f Finding, o rules.Outcome, onList bool, r *rules.Rules) string {
	// 1. the curated list first: a CVE off the list is out whatever its score
	if !onList {
		return fmt.Sprintf("group %s is not on the curated list", f.Component.Group)
	}

	// 2. no score at all
	if f.Score == nil {
		return "unscored, not on the KEV list"
	}

	// 3. a score under the bar
	score := *f.Score
	switch {
	case score >= 6.0 && score < r.Bands.High:
		return fmt.Sprintf("score %.1f, no signal in the 6.0 to 6.9 window", score)
	default:
		return fmt.Sprintf("score %.1f, below the 6.0 to 6.9 window and not on the KEV list", score)
	}
}

// The order of the backlog: KEV first, then the priority band, then the score,
// then EPSS, then the CVE and the library so the file is stable.
var priorityOrder = map[string]int{
	rules.P0: 0,
	rules.P1: 1,
	rules.P2: 2,
	rules.P3: 3,
	rules.P4: 4,
}

func sortEntries(entries []book.Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a := entries[i]
		b := entries[j]
		return before(a.CISAKEV, b.CISAKEV, a.Priority, b.Priority, a.CVSS, b.CVSS, a.EPSSPercentile, b.EPSSPercentile, a.CVE, b.CVE, a.Library, b.Library)
	})
}

func sortExcluded(entries []Excluded) {
	sort.SliceStable(entries, func(i, j int) bool {
		a := entries[i]
		b := entries[j]
		return before(a.CISAKEV, b.CISAKEV, a.Priority, b.Priority, a.CVSS, b.CVSS, a.EPSSPercentile, b.EPSSPercentile, a.CVE, b.CVE, a.Library, b.Library)
	})
}

// before is the one ordering rule, shared by both lists.
func before(aKEV, bKEV bool, aPrio, bPrio string, aScore, bScore float64, aEPSS, bEPSS *float64, aCVE, bCVE, aLib, bLib string) bool {
	if aKEV != bKEV {
		return aKEV
	}
	if priorityOrder[aPrio] != priorityOrder[bPrio] {
		return priorityOrder[aPrio] < priorityOrder[bPrio]
	}
	if aScore != bScore {
		return aScore > bScore
	}
	ae := epssOf(aEPSS)
	be := epssOf(bEPSS)
	if ae != be {
		return ae > be
	}
	if aCVE != bCVE {
		return aCVE < bCVE
	}
	return aLib < bLib
}

func epssOf(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// Header is what the two files carry before their entries.
type Header struct {
	Title         string `json:"title"`
	StandardsPack string `json:"standards_pack"`
	Generated     string `json:"generated"`
}

// backlogFile is cve-backlog.json as written.
type backlogFile struct {
	SchemaVersion string       `json:"schema_version"`
	Title         string       `json:"title"`
	StandardsPack string       `json:"standards_pack"`
	Generated     string       `json:"generated"`
	EntrySchema   string       `json:"entry_schema"`
	Entries       []book.Entry `json:"entries"`
}

// excludedFile is cve-excluded.json as written.
type excludedFile struct {
	SchemaVersion string     `json:"schema_version"`
	Title         string     `json:"title"`
	StandardsPack string     `json:"standards_pack"`
	Generated     string     `json:"generated"`
	EntrySchema   string     `json:"entry_schema"`
	Entries       []Excluded `json:"entries"`
}

// WriteBacklog writes cve-backlog.json in the backlog's order.
func WriteBacklog(path string, h Header, entries []book.Entry) error {
	sortEntries(entries)
	if entries == nil {
		entries = []book.Entry{}
	}
	f := backlogFile{
		SchemaVersion: book.SchemaVersion,
		Title:         h.Title,
		StandardsPack: h.StandardsPack,
		Generated:     h.Generated,
		EntrySchema:   "cve-backlog-entry-" + book.SchemaVersion + ".schema.json",
		Entries:       entries,
	}
	return writeJSON(path, f)
}

// WriteExcluded writes cve-excluded.json, the same shape plus a reason per entry.
func WriteExcluded(path string, h Header, entries []Excluded) error {
	sortExcluded(entries)
	if entries == nil {
		entries = []Excluded{}
	}
	f := excludedFile{
		SchemaVersion: book.SchemaVersion,
		Title:         h.Title,
		StandardsPack: h.StandardsPack,
		Generated:     h.Generated,
		EntrySchema:   "cve-backlog-entry-" + book.SchemaVersion + ".schema.json",
		Entries:       entries,
	}
	return writeJSON(path, f)
}

// writeJSON writes one file, indented by one space as the generator did, with a final newline.
func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", " ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

// String is a short line for a log: the CVE, the component and the score.
func (f Finding) String() string {
	score := "unscored"
	if f.Score != nil {
		score = fmt.Sprintf("%.1f %s", *f.Score, f.CVSSSource)
	}
	parts := []string{f.CVE, f.Component.String(), score}
	if f.KEV {
		parts = append(parts, "KEV")
	}
	return strings.Join(parts, " ")
}
