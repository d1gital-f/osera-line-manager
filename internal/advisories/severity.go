// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package advisories

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// OSV's batch answer carries ids only. The severity word (CRITICAL, HIGH, MODERATE, LOW)
// lives on the full record, on GitHub's advisories; NVD's CVE records carry a vector and no
// word, so for a CVE the word is read from its GHSA alias. Each record is read once and
// kept in a cache file next to the status records.

type record struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Modified string   `json:"modified"`
	Database struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// resolved is what one OSV record gives us: the CVE id behind a GHSA id, and the severity word.
type resolved struct {
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
}

// Resolve gives every advisory its CVE id (a GHSA id is replaced by its CVE alias when there
// is one) and its severity, reading OSV records through a cache.
func (c *Client) Resolve(ctx context.Context, advs []status.Advisory, cachePath string) ([]status.Advisory, error) {
	// 1. the cache: id -> what its record said
	cache := map[string]resolved{}
	if raw, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(raw, &cache)
	}

	// 2. the ids to resolve, once each
	var missing []string
	seen := map[string]bool{}
	for _, a := range advs {
		if _, known := cache[a.CVE]; known || seen[a.CVE] {
			continue
		}
		seen[a.CVE] = true
		missing = append(missing, a.CVE)
	}

	// 3. read the missing records, eight at a time
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	var firstErr error
	for _, id := range missing {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := c.resolve(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			cache[id] = res
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	// 4. the cache written back, the advisories filled
	if cachePath != "" {
		if raw, err := json.MarshalIndent(cache, "", "  "); err == nil {
			_ = os.WriteFile(cachePath, raw, 0o644)
		}
	}
	for i := range advs {
		res := cache[advs[i].CVE]
		if res.CVE != "" {
			advs[i].CVE = res.CVE
		}
		advs[i].Severity = severityOf(res.Severity)
	}
	return advs, nil
}

// resolve reads one record: the CVE behind a GHSA id, and the severity word, which a CVE
// record from NVD does not carry, so it is read from the GHSA alias.
func (c *Client) resolve(ctx context.Context, id string) (resolved, error) {
	rec, err := c.record(ctx, id)
	if err != nil {
		return resolved{}, err
	}
	out := resolved{CVE: id, Severity: rec.Database.Severity}
	for _, alias := range rec.Aliases {
		if strings.HasPrefix(alias, "CVE-") && strings.HasPrefix(id, "GHSA-") {
			out.CVE = alias
		}
	}
	if out.Severity == "" {
		for _, alias := range rec.Aliases {
			if !strings.HasPrefix(alias, "GHSA-") {
				continue
			}
			ghsa, err := c.record(ctx, alias)
			if err != nil {
				return resolved{}, err
			}
			if ghsa.Database.Severity != "" {
				out.Severity = ghsa.Database.Severity
				break
			}
		}
	}
	return out, nil
}

func (c *Client) record(ctx context.Context, id string) (*record, error) {
	url := strings.TrimSuffix(c.URL, "/querybatch") + "/vulns/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV record %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &record{ID: id}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV record %s: HTTP %d", id, resp.StatusCode)
	}
	var rec record
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return nil, fmt.Errorf("OSV record %s: %w", id, err)
	}
	return &rec, nil
}
