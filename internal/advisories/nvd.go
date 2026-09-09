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
	"time"
)

// The book scores a CVE on the CVSS 3.1 base score as recorded at NVD, NVD's own
// analysis first, else the CNA's score as recorded there. The line manager reads
// the same, so the two never disagree on a number. Without an API key NVD allows
// five requests per thirty seconds; the cache keeps every answer.

// NVD reads one CVE record at a time.
type NVD struct {
	HTTP   *http.Client
	URL    string
	APIKey string
	Pause  time.Duration
}

// NewNVD returns a client paced for NVD's public limit, faster with NVD_API_KEY set.
func NewNVD() *NVD {
	n := &NVD{HTTP: &http.Client{Timeout: 60 * time.Second}, URL: "https://services.nvd.nist.gov/rest/json/cves/2.0", APIKey: os.Getenv("NVD_API_KEY"), Pause: 6500 * time.Millisecond}
	if n.APIKey != "" {
		n.Pause = 700 * time.Millisecond
	}
	return n
}

// Score returns NVD's CVSS 3.1 base score for a CVE (0 when NVD has none yet) and the record's status.
func (n *NVD) Score(ctx context.Context, cve string) (float64, string, error) {
	// 1. the record
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.URL+"?cveId="+cve, nil)
	if err != nil {
		return 0, "", err
	}
	if n.APIKey != "" {
		req.Header.Set("apiKey", n.APIKey)
	}
	resp, err := n.HTTP.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("NVD %s: %w", cve, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, "not at NVD", nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("NVD %s: HTTP %d", cve, resp.StatusCode)
	}
	var res struct {
		Vulnerabilities []struct {
			CVE struct {
				VulnStatus string `json:"vulnStatus"`
				Metrics    struct {
					V31 []struct {
						Source   string `json:"source"`
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return 0, "", fmt.Errorf("NVD %s: %w", cve, err)
	}
	if len(res.Vulnerabilities) == 0 {
		return 0, "not at NVD", nil
	}
	rec := res.Vulnerabilities[0].CVE

	// 2. NVD's own 3.1 analysis first, else the first 3.1 score recorded (the CNA's)
	for _, m := range rec.Metrics.V31 {
		if m.Source == "nvd@nist.gov" {
			return m.CVSSData.BaseScore, rec.VulnStatus, nil
		}
	}
	if len(rec.Metrics.V31) > 0 {
		return rec.Metrics.V31[0].CVSSData.BaseScore, rec.VulnStatus, nil
	}
	return 0, rec.VulnStatus, nil
}
