// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The four public sources, each read through the cache. One JSON file per
// source in CacheDir, saved after every fetch, so a pass cut short loses
// nothing and a CVE is fetched from NVD once ever.

// osvRecord is what one OSV record gives us.
type osvRecord struct {
	ID               string        `json:"id"`
	Aliases          []string      `json:"aliases"`
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
	Affected         []osvAffected `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// osvAffected is one package block of a record.
type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

// fixedFor says the record names a fixed version for a package.
func (r *osvRecord) fixedFor(name string) bool {
	for _, a := range r.Affected {
		if !strings.EqualFold(a.Package.Name, name) {
			continue
		}
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if ev.Fixed != "" {
					return true
				}
			}
		}
	}
	return false
}

// nvdScore is what NVD said about one CVE, and whether it was asked.
type nvdScore struct {
	Score   float64 `json:"score"`
	Source  string  `json:"source"`
	Status  string  `json:"status"`
	Checked bool    `json:"checked"`
}

// cache is the four files, loaded at the start of a pass.
type cache struct {
	dir     string
	records map[string]*osvRecord
	kev     kevFile
	epss    map[string]epssEntry
	nvd     map[string]nvdScore
}

// epssEntry is what FIRST said about one CVE: a percentile, or nothing, once asked.
type epssEntry struct {
	Percentile *float64 `json:"percentile"`
	Asked      bool     `json:"asked"`
}

// kevFile is the KEV catalog as fetched, with the time it was fetched.
type kevFile struct {
	Fetched string          `json:"fetched"`
	CVEs    map[string]bool `json:"cves"`
}

// openCache loads what earlier passes learnt.
func (s *Scanner) openCache() (*cache, error) {
	c := &cache{dir: s.CacheDir, records: map[string]*osvRecord{}, epss: map[string]epssEntry{}, nvd: map[string]nvdScore{}}
	if s.CacheDir == "" {
		return c, nil
	}
	err := os.MkdirAll(s.CacheDir, 0o755)
	if err != nil {
		return nil, errorf("cache directory: %w", err)
	}
	load(filepath.Join(s.CacheDir, "osv-records.json"), &c.records)
	load(filepath.Join(s.CacheDir, "kev.json"), &c.kev)
	load(filepath.Join(s.CacheDir, "epss.json"), &c.epss)
	load(filepath.Join(s.CacheDir, "nvd.json"), &c.nvd)
	return c, nil
}

// load reads one cache file; a missing or broken file is an empty one.
func load(path string, into any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, into)
}

// save writes one cache file, no error: a cache that cannot be written only costs a refetch.
func (c *cache) save(name string, value any) {
	if c.dir == "" {
		return
	}
	raw, err := json.MarshalIndent(value, "", " ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(c.dir, name), raw, 0o644)
}

// osvBatch asks OSV which advisories touch each component, a thousand per call.
// The answer is per component: the advisory ids, in OSV's order.
func (s *Scanner) osvBatch(ctx context.Context, components []Component) (map[string][]string, error) {
	type query struct {
		Version string `json:"version"`
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}
	hits := map[string][]string{}
	for start := 0; start < len(components); start += 1000 {
		// 1. one chunk of queries
		end := min(start+1000, len(components))
		var queries []query
		for _, c := range components[start:end] {
			var q query
			q.Version = c.Version
			q.Package.Name = c.Name()
			q.Package.Ecosystem = "Maven"
			queries = append(queries, q)
		}
		body, err := json.Marshal(map[string]any{"queries": queries})
		if err != nil {
			return nil, err
		}

		// 2. the call, OSV answers in the same order
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = s.postJSON(ctx, s.OSVURL+"/querybatch", body, &res)
		if err != nil {
			return nil, errorf("OSV batch: %w", err)
		}
		if len(res.Results) != end-start {
			return nil, errorf("OSV answered %d results for %d queries", len(res.Results), end-start)
		}

		// 3. the ids per component
		for i, r := range res.Results {
			c := components[start+i]
			for _, v := range r.Vulns {
				hits[c.String()] = append(hits[c.String()], v.ID)
			}
		}
	}
	return hits, nil
}

// osvRecord reads one record, from the cache when it is there.
func (s *Scanner) osvRecord(ctx context.Context, c *cache, id string) (*osvRecord, error) {
	// 1. the cache
	if rec, known := c.records[id]; known {
		return rec, nil
	}

	// 2. the record
	var rec osvRecord
	status, err := s.getJSON(ctx, s.OSVURL+"/vulns/"+id, nil, &rec)
	if err != nil {
		return nil, errorf("OSV record %s: %w", id, err)
	}
	if status == http.StatusNotFound {
		rec = osvRecord{ID: id}
	}
	if rec.Summary == "" && rec.Details != "" {
		rec.Summary = firstLine(rec.Details)
	}

	// 3. kept
	c.records[id] = &rec
	c.save("osv-records.json", c.records)
	return &rec, nil
}

// kev reads the CISA KEV list, once a day.
func (s *Scanner) kev(ctx context.Context, c *cache) (map[string]bool, error) {
	// 1. fresh enough in the cache
	if c.kev.CVEs != nil {
		fetched, err := time.Parse(time.RFC3339, c.kev.Fetched)
		if err == nil && s.Now().Sub(fetched) < s.KEVMaxAge {
			return c.kev.CVEs, nil
		}
	}

	// 2. the list
	var res struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	_, err := s.getJSON(ctx, s.KEVURL, nil, &res)
	if err != nil {
		return nil, errorf("KEV: %w", err)
	}
	cves := map[string]bool{}
	for _, v := range res.Vulnerabilities {
		cves[v.CVEID] = true
	}

	// 3. kept with the time
	c.kev = kevFile{Fetched: s.Now().UTC().Format(time.RFC3339), CVEs: cves}
	c.save("kev.json", c.kev)
	return cves, nil
}

// epss reads FIRST's percentile for the CVEs not asked yet, a hundred per call.
// A CVE FIRST has no score for is remembered as asked, so it is not asked again.
func (s *Scanner) epss(ctx context.Context, c *cache, cves []string) (map[string]float64, error) {
	// 1. the ones to ask for
	var missing []string
	for _, cve := range cves {
		if !c.epss[cve].Asked {
			missing = append(missing, cve)
		}
	}

	// 2. a hundred per call
	for start := 0; start < len(missing); start += 100 {
		end := min(start+100, len(missing))
		var res struct {
			Data []struct {
				CVE        string `json:"cve"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		q := url.Values{}
		q.Set("cve", strings.Join(missing[start:end], ","))
		_, err := s.getJSON(ctx, s.EPSSURL+"?"+q.Encode(), nil, &res)
		if err != nil {
			return nil, errorf("EPSS: %w", err)
		}
		for _, cve := range missing[start:end] {
			c.epss[cve] = epssEntry{Asked: true}
		}
		for _, row := range res.Data {
			var p float64
			_, err := parseFloat(row.Percentile, &p)
			if err != nil {
				continue
			}
			c.epss[row.CVE] = epssEntry{Percentile: &p, Asked: true}
		}
		c.save("epss.json", c.epss)
	}

	// 3. the percentiles known
	out := map[string]float64{}
	for cve, e := range c.epss {
		if e.Percentile != nil {
			out[cve] = *e.Percentile
		}
	}
	return out, nil
}

// nvd reads NVD's CVSS 3.1 base score for the CVEs not read yet, one call each
// at NVD's pace. NVD's own analysis first, else the CNA's as recorded there.
func (s *Scanner) nvd(ctx context.Context, c *cache, cves []string) (map[string]nvdScore, error) {
	for _, cve := range cves {
		// 1. already read
		if c.nvd[cve].Checked {
			continue
		}

		// 2. the record
		score, err := s.nvdOne(ctx, cve)
		if err != nil {
			// NVD unreachable or throttled: no score this pass, retried next pass
			c.nvd[cve] = nvdScore{Status: "NVD not read: " + err.Error()}
			c.save("nvd.json", c.nvd)
			continue
		}
		c.nvd[cve] = score
		c.save("nvd.json", c.nvd)

		// 3. the pace
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.NVDPause):
		}
	}
	return c.nvd, nil
}

// nvdOne reads one CVE record at NVD.
func (s *Scanner) nvdOne(ctx context.Context, cve string) (nvdScore, error) {
	headers := map[string]string{}
	if s.NVDAPIKey != "" {
		headers["apiKey"] = s.NVDAPIKey
	}
	var res struct {
		Vulnerabilities []struct {
			CVE struct {
				VulnStatus string `json:"vulnStatus"`
				Metrics    struct {
					V31 []struct {
						Source   string `json:"source"`
						Type     string `json:"type"`
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	status, err := s.getJSON(ctx, s.NVDURL+"?cveId="+cve, headers, &res)
	if err != nil {
		return nvdScore{}, err
	}
	if status == http.StatusNotFound || len(res.Vulnerabilities) == 0 {
		return nvdScore{Status: "not at NVD", Checked: true}, nil
	}
	rec := res.Vulnerabilities[0].CVE

	// NVD's own 3.1 analysis first, else the first 3.1 score recorded, the CNA's
	for _, m := range rec.Metrics.V31 {
		if m.Source == "nvd@nist.gov" || m.Type == "Primary" {
			return nvdScore{Score: m.CVSSData.BaseScore, Source: "nvd", Status: rec.VulnStatus, Checked: true}, nil
		}
	}
	if len(rec.Metrics.V31) > 0 {
		return nvdScore{Score: rec.Metrics.V31[0].CVSSData.BaseScore, Source: "cna", Status: rec.VulnStatus, Checked: true}, nil
	}
	return nvdScore{Status: rec.VulnStatus, Checked: true}, nil
}

// getJSON reads one JSON document; a 404 is returned as the status, not an error.
func (s *Scanner) getJSON(ctx context.Context, u string, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "osera-line-manager")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, json.Unmarshal(raw, out)
}

// postJSON sends one JSON document and reads the answer.
func (s *Scanner) postJSON(ctx context.Context, u string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "osera-line-manager")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errorf("POST %s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// firstLine is the first line of a text, trimmed, at most two hundred characters.
func firstLine(s string) string {
	line := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}
