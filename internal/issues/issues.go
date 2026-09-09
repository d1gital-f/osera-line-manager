// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package issues finds where each CVE's issue lives in the organisation, through
// GitHub's issue search. One query per run, paged, whatever the number of CVEs.
package issues

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Client searches one organisation or user account.
type Client struct {
	Owner string
	HTTP  *http.Client
	Token string
}

// New returns a client with sane timeouts.
func New(owner, token string) *Client {
	return &Client{Owner: owner, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

var cveInTitle = regexp.MustCompile(`(CVE-[0-9]{4}-[0-9]+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})`)

// Find returns one Issue per CVE found in an issue title anywhere under the owner.
// When a CVE has more than one issue the one outside the backlog repository wins,
// it is the one a producer took.
func (c *Client) Find(ctx context.Context, backlogRepo string) ([]status.Issue, error) {
	found := map[string]status.Issue{}
	for page := 1; page <= 10; page++ {
		// 1. the query: issues with a CVE id in the title, under this owner
		q := url.Values{}
		q.Set("q", fmt.Sprintf("CVE- in:title user:%s is:issue", c.Owner))
		q.Set("per_page", "100")
		q.Set("page", fmt.Sprint(page))
		var res struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				Title         string `json:"title"`
				RepositoryURL string `json:"repository_url"`
			} `json:"items"`
		}
		if err := c.getJSON(ctx, "https://api.github.com/search/issues?"+q.Encode(), &res); err != nil {
			return nil, err
		}

		// 2. one entry per CVE, the patch repository wins over backlog
		for _, it := range res.Items {
			cve := cveInTitle.FindString(it.Title)
			if cve == "" {
				continue
			}
			repo := it.RepositoryURL[len("https://api.github.com/repos/")+len(c.Owner)+1:]
			prev, seen := found[cve]
			if !seen || (prev.Repository == backlogRepo && repo != backlogRepo) {
				found[cve] = status.Issue{CVE: cve, Repository: repo}
			}
		}
		if len(res.Items) < 100 {
			break
		}
	}

	// 3. as a list
	out := make([]status.Issue, 0, len(found))
	for _, is := range found {
		out = append(out, is)
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
