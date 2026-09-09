// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package advisories asks OSV which vulnerabilities are known for the exact
// coordinates the line uses, one batch query per run. The book was built from
// the same source, so a CVE OSV has and the book does not is a new one.
package advisories

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Client talks to api.osv.dev.
type Client struct {
	HTTP *http.Client
	URL  string
}

// New returns a client with sane timeouts.
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}, URL: "https://api.osv.dev/v1/querybatch"}
}

// Known returns every CVE OSV lists for the coordinates of the entries, one Advisory per CVE and coordinate.
func (c *Client) Known(ctx context.Context, entries []book.Entry) ([]status.Advisory, error) {
	// 1. one query per distinct coordinate
	type query struct {
		Version string `json:"version"`
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}
	var queries []query
	var coords []book.Entry
	seen := map[string]bool{}
	for _, e := range entries {
		key := e.Library + "@" + e.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		var q query
		q.Version = e.Version
		q.Package.Name = e.Library
		q.Package.Ecosystem = "Maven"
		queries = append(queries, q)
		coords = append(coords, e)
	}

	// 2. the batch call, OSV answers in the same order
	var out []status.Advisory
	for start := 0; start < len(queries); start += 1000 {
		end := min(start+1000, len(queries))
		body, err := json.Marshal(map[string]any{"queries": queries[start:end]})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("OSV query: %w", err)
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID       string   `json:"id"`
					Aliases  []string `json:"aliases"`
					Severity []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					} `json:"severity"`
					DatabaseSpecific struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("OSV answer: %w", err)
		}
		if len(res.Results) != end-start {
			return nil, fmt.Errorf("OSV answered %d results for %d queries", len(res.Results), end-start)
		}

		// 3. the CVE id: OSV's own id when it is one, else the CVE alias, else the GHSA id
		for i, r := range res.Results {
			e := coords[start+i]
			for _, v := range r.Vulns {
				id := cveOf(v.ID, v.Aliases)
				if id == "" {
					continue
				}
				out = append(out, status.Advisory{CVE: id, Library: e.Library, Version: e.Version, Severity: severityOf(v.DatabaseSpecific.Severity)})
			}
		}
	}
	return out, nil
}

// severityOf turns OSV's word (CRITICAL, HIGH, MODERATE, LOW) into the floor of its CVSS band,
// enough to tell a Critical from a Low without parsing vectors. 0 when OSV says nothing.
func severityOf(word string) float64 {
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

func cveOf(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if strings.HasPrefix(id, "GHSA-") {
		return id
	}
	return ""
}
