// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// The dev only advisory source: a file in OSV's record shape the line manager
// reads next to OSV in the dev organisation, to invent a CVE on a package of a
// dev line and watch the line change. Never present in production.

// devFile is the file as written: a note and the records.
type devFile struct {
	Source string      `json:"source"`
	Vulns  []osvRecord `json:"vulns"`
}

// devAdvisories reads the file, if any, and adds its records to the hits of the
// components they affect. Returns the records by id.
func (s *Scanner) devAdvisories(components []Component, hits map[string][]string) (map[string]*osvRecord, error) {
	out := map[string]*osvRecord{}
	if s.DevAdvisories == "" {
		return out, nil
	}

	// 1. the file
	raw, err := os.ReadFile(s.DevAdvisories)
	if err != nil {
		return nil, errorf("dev advisories: %w", err)
	}
	var f devFile
	err = json.Unmarshal(raw, &f)
	if err != nil {
		return nil, errorf("dev advisories: %w", err)
	}

	// 2. each record against each component
	for i := range f.Vulns {
		rec := &f.Vulns[i]
		if rec.Summary == "" && rec.Details != "" {
			rec.Summary = firstLine(rec.Details)
		}
		for _, c := range components {
			if !rec.applies(c) {
				continue
			}
			out[rec.ID] = rec
			hits[c.String()] = append(hits[c.String()], rec.ID)
		}
	}
	return out, nil
}

// applies says a record affects a component: the package name and ecosystem
// match, and the version is listed or inside a range.
func (r *osvRecord) applies(c Component) bool {
	for _, a := range r.Affected {
		if a.Package.Ecosystem != "Maven" || !strings.EqualFold(a.Package.Name, c.Name()) {
			continue
		}
		for _, v := range a.Versions {
			if v == c.Version {
				return true
			}
		}
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
				continue
			}
			if inRange(c.Version, rg.Events) {
				return true
			}
		}
	}
	return false
}

// inRange walks the events in order: introduced opens, fixed closes.
func inRange(version string, events []struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}) bool {
	open := false
	for _, ev := range events {
		if ev.Introduced != "" {
			if ev.Introduced == "0" || compareVersions(version, ev.Introduced) >= 0 {
				open = true
			} else {
				open = false
			}
		}
		if ev.Fixed != "" && open {
			if compareVersions(version, ev.Fixed) >= 0 {
				open = false
			} else {
				return true
			}
		}
	}
	return open
}

// compareVersions orders two Maven version strings the simple way: split on
// dots and dashes, numeric segments compared as numbers, the rest as text, the
// shorter one first when all shared segments are equal. A stand in until a
// Maven aware comparison lands; enough for the dev file.
func compareVersions(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		if aErr == nil && bErr == nil {
			if an != bn {
				return sign(an - bn)
			}
			continue
		}
		if as[i] != bs[i] {
			return strings.Compare(as[i], bs[i])
		}
	}
	return sign(len(as) - len(bs))
}

// splitVersion splits on dots and dashes.
func splitVersion(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-'
	})
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}

// parseFloat reads a number written as text, as FIRST writes percentiles.
func parseFloat(s string, into *float64) (bool, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return false, err
	}
	*into = f
	return true, nil
}
