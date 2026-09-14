// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package scan asks the public advisory sources what is known about every
// component of a line and turns the answers into findings: one CVE on one
// component with its score, its KEV and EPSS facts and its summary. The same
// four sources the backlog generator used (OSV, CISA KEV, FIRST EPSS, NVD),
// read through a disk cache so nothing is fetched twice, plus a dev only file
// in OSV's shape for a CVE that does not exist yet. Apply then puts the rules
// on the findings and splits them into the backlog and the excluded list.
package scan

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Component is one coordinate of a line's graph.
type Component struct {
	Group    string
	Artifact string
	Version  string
}

// Name is the package name as OSV writes a Maven package: group:artifact.
func (c Component) Name() string {
	return c.Group + ":" + c.Artifact
}

// String is group:artifact@version.
func (c Component) String() string {
	return c.Name() + "@" + c.Version
}

// Finding is one CVE on one component, with everything the rules read.
type Finding struct {
	CVE       string
	Component Component
	// Score is the CVSS base score, nil when no source has a number.
	Score *float64
	// CVSSSource says where Score came from: nvd (NVD's own analysis), cna (the
	// reporting organisation's score as recorded at NVD), osv-word (the floor of
	// the severity word on the advisory) or empty.
	CVSSSource     string
	KEV            bool
	EPSSPercentile *float64
	Summary        string
	Aliases        []string
	// FixedByUpgrade says the advisory names a fixed version for this package.
	FixedByUpgrade bool
}

// Scanner holds the addresses of the sources and the cache.
type Scanner struct {
	HTTP *http.Client
	// OSVURL is the API root, https://api.osv.dev/v1.
	OSVURL  string
	KEVURL  string
	EPSSURL string
	NVDURL  string
	// NVDAPIKey lifts NVD's public pace; NVDPause is the time between NVD calls.
	NVDAPIKey string
	NVDPause  time.Duration
	// CacheDir holds one JSON file per source, saved after every fetch.
	CacheDir string
	// DevAdvisories is a file in OSV's shape read next to OSV. Dev only, empty in production.
	DevAdvisories string
	// KEVMaxAge says how old the cached KEV list may be before it is fetched again.
	KEVMaxAge time.Duration
	// Now is the clock, replaceable in tests.
	Now func() time.Time
	// Logf, when set, is told what the sources answered.
	Logf func(format string, a ...any)
}

// New returns a scanner on the public sources, paced for NVD's public limit,
// faster with NVD_API_KEY set.
func New(cacheDir string) *Scanner {
	s := &Scanner{
		HTTP:      &http.Client{Timeout: 60 * time.Second},
		OSVURL:    "https://api.osv.dev/v1",
		KEVURL:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		EPSSURL:   "https://api.first.org/data/v1/epss",
		NVDURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		NVDAPIKey: os.Getenv("NVD_API_KEY"),
		NVDPause:  6500 * time.Millisecond,
		CacheDir:  cacheDir,
		KEVMaxAge: 24 * time.Hour,
		Now:       time.Now,
	}
	if s.NVDAPIKey != "" {
		s.NVDPause = 700 * time.Millisecond
	}
	return s
}

// Scan returns every finding on the components, one per CVE per component.
func (s *Scanner) Scan(ctx context.Context, components []Component) ([]Finding, error) {
	// 1. the cache, one file per source
	cache, err := s.openCache()
	if err != nil {
		return nil, err
	}

	// 2. the distinct components, in a stable order
	distinct := distinctComponents(components)

	// 3. OSV: which advisory ids touch which component, one batch call per thousand
	hits, err := s.osvBatch(ctx, distinct)
	if err != nil {
		return nil, err
	}

	// 4. the dev only file, merged as if OSV had answered it
	devRecords, err := s.devAdvisories(distinct, hits)
	if err != nil {
		return nil, err
	}

	// 5. every advisory record once: aliases, summary, severity, fixed versions
	records := map[string]*osvRecord{}
	for id, rec := range devRecords {
		records[id] = rec
	}
	for _, ids := range hits {
		for _, id := range ids {
			if _, known := records[id]; known {
				continue
			}
			rec, err := s.osvRecord(ctx, cache, id)
			if err != nil {
				return nil, err
			}
			records[id] = rec
		}
	}

	// 6. the canonical CVE id of every record, and the CVE ids to score
	canonical := map[string]string{}
	var cves []string
	seenCVE := map[string]bool{}
	for id, rec := range records {
		cve := canonicalID(id, rec.Aliases)
		canonical[id] = cve
		if strings.HasPrefix(cve, "CVE-") && !seenCVE[cve] {
			seenCVE[cve] = true
			cves = append(cves, cve)
		}
	}
	sort.Strings(cves)

	// 7. KEV, EPSS and NVD for those CVEs
	kev, err := s.kev(ctx, cache)
	if err != nil {
		return nil, err
	}
	epss, err := s.epss(ctx, cache, cves)
	if err != nil {
		return nil, err
	}
	nvd, err := s.nvd(ctx, cache, cves)
	if err != nil {
		return nil, err
	}

	// 8. one finding per CVE per component
	var out []Finding
	seen := map[string]bool{}
	for _, c := range distinct {
		for _, id := range hits[c.String()] {
			rec := records[id]
			cve := canonical[id]
			key := cve + " " + c.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			f := Finding{CVE: cve, Component: c, Summary: rec.Summary, Aliases: rec.Aliases, KEV: kev[cve]}
			if p, ok := epss[cve]; ok {
				f.EPSSPercentile = &p
			}
			f.Score, f.CVSSSource = scoreOf(nvd[cve], rec)
			f.FixedByUpgrade = rec.fixedFor(c.Name())
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		return out[i].Component.String() < out[j].Component.String()
	})
	return out, nil
}

// distinctComponents keeps each coordinate once, sorted.
func distinctComponents(components []Component) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, c := range components {
		if seen[c.String()] {
			continue
		}
		seen[c.String()] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}

// canonicalID is the CVE behind an advisory id: the id itself when it is a CVE,
// else its first CVE alias, else the id as it is (a GHSA with no CVE yet).
func canonicalID(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

// scoreOf picks the score: NVD's own analysis, else the CNA's as recorded at
// NVD, else the floor of the advisory's severity word, else nothing.
func scoreOf(n nvdScore, rec *osvRecord) (*float64, string) {
	if n.Checked && n.Score > 0 {
		score := n.Score
		return &score, n.Source
	}
	word := severityWord(rec)
	floor := wordFloor(word)
	if floor > 0 {
		return &floor, "osv-word"
	}
	return nil, ""
}

// severityWord is the word on the record (CRITICAL, HIGH, MODERATE, LOW), or empty.
func severityWord(rec *osvRecord) string {
	if rec == nil {
		return ""
	}
	return rec.DatabaseSpecific.Severity
}

// wordFloor turns a severity word into the floor of its CVSS band, enough to
// tell a Critical from a Low without a vector. 0 when there is no word.
func wordFloor(word string) float64 {
	switch strings.ToUpper(word) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.0
	case "MODERATE", "MEDIUM":
		return 4.0
	case "LOW":
		return 0.1
	}
	return 0
}

// errorf is fmt.Errorf with the package name in front, so a log line says where it came from.
func errorf(format string, a ...any) error {
	return fmt.Errorf("scan: "+format, a...)
}
