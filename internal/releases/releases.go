// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package releases reads the release repository: what sits in it is what the
// gate promoted. One search per pass lists every coordinate; the evidence file
// the gate published next to a jar says which CVEs that release fixes. Nothing
// here decides anything, it reads.
package releases

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PatchSeparator is what REL-003 puts between the base version and the patch
// number on a Java coordinate: 5.3.39+osera-patch.001.
const PatchSeparator = "+osera-patch."

// maxBody caps any response body held in memory.
const maxBody = 4 << 20

// ErrNoEvidence says the release repository holds no evidence file next to the coordinate.
var ErrNoEvidence = errors.New("no evidence file next to the coordinate")

// Client reads one Nexus instance with the line manager's own account.
type Client struct {
	BaseURL string
	User    string
	Pass    string
	HTTP    *http.Client
}

// New returns a client with sane timeouts.
func New(baseURL, user, pass string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		User:    user,
		Pass:    pass,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// Coordinate is one Maven artifact at one version in the release repository.
type Coordinate struct {
	Group    string
	Artifact string
	Version  string
	// Base is the upstream version the patch was made on; Patch is the patch
	// number. Both empty when the version is not in the REL-003 patched form.
	Base  string
	Patch string
	// Assets are the paths of the files under the coordinate, as Nexus lists them.
	Assets []string
}

// NewCoordinate builds a coordinate and splits its version by REL-003, the two
// ratified forms of OSERA-SP-0.1.0, the same rule the fitness library applies:
//
//	generic  2.14.2+osera-patch.001    -> base 2.14.2,       patch 001
//	Java     5.3.39.1-osera-00001      -> base 5.3.39,       patch 00001  (REL-003-JAVA, the .N the patch added dropped, as the gate reads it)
//	Java     1.33.1-osera-00001        -> base 1.33,         patch 00001
//	Java     5.6.15.Final-osera-00001  -> base 5.6.15.Final, patch 00001  (qualified base)
func NewCoordinate(group, artifact, version string) Coordinate {
	c := Coordinate{Group: group, Artifact: artifact, Version: version}

	// 1. the generic form: everything before the separator is the base
	before, after, found := strings.Cut(version, PatchSeparator)
	if found && before != "" && after != "" {
		c.Base = before
		c.Patch = after
		return c
	}

	// 2. the Java form, read the way the gate reads it (REL-003-JAVA.CHECK-001): the
	//    shortest base, then an optional .N the patch added, then -osera-NNNNN
	m := carePattern.FindStringSubmatch(version)
	if m == nil {
		return c
	}
	c.Base = m[1]
	c.Patch = m[3]
	return c
}

// carePattern is the gate's own expression for the Java form: 5.3.39.1-osera-00001 is
// base 5.3.39, 1.33.1-osera-00001 is base 1.33, 3.10.6.Final-osera-00001 is base 3.10.6.Final.
var carePattern = regexp.MustCompile(`^(.+?)(\.[0-9]+)?-osera-([0-9]{5})$`)

// String is the coordinate as the backlog writes it, group:artifact@version.
func (c Coordinate) String() string {
	return c.Group + ":" + c.Artifact + "@" + c.Version
}

// Patched says whether the version carries a REL-003 patch number.
func (c Coordinate) Patched() bool {
	return c.Patch != ""
}

// Evidence is the producer's patch evidence file as the gate published it next to the jar.
type Evidence struct {
	Schema        string `yaml:"schema"`
	Producer      string `yaml:"producer"`
	Release       string `yaml:"release"`
	Baseline      string `yaml:"baseline"`
	Fixes         []Fix  `yaml:"fixes"`
	Tests         Tests  `yaml:"tests"`
	BytecodeLevel int    `yaml:"bytecode_level"`
}

// Fix is one CVE the release fixes, with the upstream reference the producer gave.
type Fix struct {
	CVE      string `yaml:"cve"`
	Upstream string `yaml:"upstream"`
	Note     string `yaml:"note"`
}

// Tests is the test block of the evidence file.
type Tests struct {
	Commit  string `yaml:"commit"`
	Command string `yaml:"command"`
	Runtime string `yaml:"runtime"`
	Report  string `yaml:"report"`
	Result  string `yaml:"result"`
	Totals  string `yaml:"totals"`
}

// CVEs lists the CVE ids the evidence names, in order, each once.
func (e *Evidence) CVEs() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range e.Fixes {
		if f.CVE == "" {
			continue
		}
		if seen[f.CVE] {
			continue
		}
		seen[f.CVE] = true
		out = append(out, f.CVE)
	}
	return out
}

// searchPage is one page of Nexus's component search.
type searchPage struct {
	Items []struct {
		Group   string `json:"group"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Assets  []struct {
			Path string `json:"path"`
		} `json:"assets"`
	} `json:"items"`
	ContinuationToken string `json:"continuationToken"`
}

// Promoted lists every maven2 coordinate in a repository, one paged search.
func (c *Client) Promoted(ctx context.Context, repository string) ([]Coordinate, error) {
	var out []Coordinate
	token := ""
	for {
		// 1. one page of the component search
		q := url.Values{}
		q.Set("repository", repository)
		q.Set("format", "maven2")
		if token != "" {
			q.Set("continuationToken", token)
		}
		var page searchPage
		err := c.getJSON(ctx, "/service/rest/v1/search?"+q.Encode(), &page)
		if err != nil {
			return nil, fmt.Errorf("searching %s: %w", repository, err)
		}

		// 2. one coordinate per component, with its asset paths
		for _, it := range page.Items {
			coord := NewCoordinate(it.Group, it.Name, it.Version)
			for _, a := range it.Assets {
				coord.Assets = append(coord.Assets, a.Path)
			}
			out = append(out, coord)
		}

		// 3. the next page, until Nexus says there is none
		if page.ContinuationToken == "" {
			return out, nil
		}
		token = page.ContinuationToken
	}
}

// EvidencePath is where the gate publishes the evidence file for a coordinate,
// relative to the repository root.
func EvidencePath(c Coordinate) string {
	return strings.ReplaceAll(c.Group, ".", "/") + "/" + c.Artifact + "/" + c.Version + "/" + c.Artifact + "-" + c.Version + "-osera-evidence.yaml"
}

// Evidence reads the evidence file next to a coordinate in a repository.
func (c *Client) Evidence(ctx context.Context, repository string, coord Coordinate) (*Evidence, error) {
	// 1. the file, by its path under the repository
	path := "/repository/" + repository + "/" + EvidencePath(coord)
	resp, err := c.do(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading the evidence of %s: %w", coord, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", coord, ErrNoEvidence)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reading the evidence of %s: HTTP %d", coord, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("reading the evidence of %s: %w", coord, err)
	}

	// 2. the shape
	var ev Evidence
	err = yaml.Unmarshal(raw, &ev)
	if err != nil {
		return nil, fmt.Errorf("parsing the evidence of %s: %w", coord, err)
	}
	return &ev, nil
}

// do performs one GET with the client's credentials.
func (c *Client) do(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Pass)
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	return c.HTTP.Do(req)
}

// getJSON performs one GET and decodes a JSON answer.
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// Put uploads one file into a repository at a Maven path, with the client's
// credentials. A 2xx is success and so is a 409: the path exists already
// (ALLOW_ONCE), the file is there, which is what was wanted.
func (c *Client) Put(ctx context.Context, repository, path string, body []byte, contentType string) error {
	// 1. the request
	url := fmt.Sprintf("%s/repository/%s/%s", c.BaseURL, repository, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Pass)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))

	// 2. the answer
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	return fmt.Errorf("PUT %s: HTTP %d", path, resp.StatusCode)
}
