// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package source fetches the published book from the backlog repository: the
// latest v* tag through the GitHub API, the files through raw.githubusercontent.com.
// Public repository, no credential, no git binary in the image.
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Client reads one backlog repository.
type Client struct {
	Owner string
	Repo  string
	HTTP  *http.Client
	// Token is optional, it lifts GitHub's unauthenticated rate limit.
	Token string
}

// New returns a client with sane timeouts.
func New(owner, repo, token string) *Client {
	return &Client{Owner: owner, Repo: repo, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// LatestTag returns the highest v* tag of the repository, by version order, and its commit.
func (c *Client) LatestTag(ctx context.Context) (string, string, error) {
	// 1. every tag, GitHub pages at 100
	type tag struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	var all []tag
	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags?per_page=100&page=%d", c.Owner, c.Repo, page)
		var batch []tag
		if err := c.getJSON(ctx, url, &batch); err != nil {
			return "", "", err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}

	// 2. only the v* tags, newest version first
	var names []tag
	for _, t := range all {
		if strings.HasPrefix(t.Name, "v") {
			names = append(names, t)
		}
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("no v* tag on %s/%s", c.Owner, c.Repo)
	}
	sort.Slice(names, func(i, j int) bool { return versionLess(names[j].Name, names[i].Name) })
	return names[0].Name, names[0].Commit.SHA, nil
}

// File fetches one file of the repository at a tag.
func (c *Client) File(ctx context.Context, tag, path string) ([]byte, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", c.Owner, c.Repo, tag, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s at %s: %w", path, tag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s at %s: HTTP %d", path, tag, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// versionLess orders v2026.09.09 before v2026.09.10 and v1 before v2, numerically per segment.
func versionLess(a, b string) bool {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		var ai, bi int
		fmt.Sscanf(as[i], "%d", &ai)
		fmt.Sscanf(bs[i], "%d", &bi)
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}
