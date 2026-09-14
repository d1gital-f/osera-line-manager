// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Grype reads the line's CycloneDX file and answers with everything the rules
// need in one place: the advisory, the CVSS scores by source, the fix, KEV,
// EPSS. It is what a bank's scanner sees, and it replaces the four API calls
// of Scanner. The database is fetched once at start and once a day.

// GrypeScanner runs the grype binary on a CycloneDX file.
type GrypeScanner struct {
	// Binary is the grype executable, grype on PATH when empty.
	Binary string
	// DBDir holds the vulnerability database and the update stamp.
	DBDir string
	// DevAdvisories is a file in OSV's shape read next to Grype. Dev only, empty in production.
	DevAdvisories string
	// DBMaxAge says how old the database may be before UpdateDB fetches it again, a day when zero.
	DBMaxAge time.Duration
	// Timeout bounds one grype run, ten minutes when zero.
	Timeout time.Duration
	// Now is the clock, replaceable in tests.
	Now func() time.Time
	// Logf, when set, is told the detail of what grype does: the dev advisory file, the fine print.
	Logf func(format string, a ...any)
	// Say, when set, is told the lines worth a normal log: the database current, updating, updated.
	Say func(format string, a ...any)
	// version remembers what the binary answered, asked once.
	version string
}

// say logs the fine print when a logger was given.
func (g *GrypeScanner) say(format string, a ...any) {
	if g.Logf != nil {
		g.Logf(format, a...)
	}
}

// announce logs a line worth the normal level, the detail logger when there is no other.
func (g *GrypeScanner) announce(format string, a ...any) {
	if g.Say != nil {
		g.Say(format, a...)
		return
	}
	g.say(format, a...)
}

// NewGrype returns a scanner on the grype binary with the database under dbDir.
func NewGrype(binary, dbDir string) *GrypeScanner {
	return &GrypeScanner{Binary: binary, DBDir: dbDir, DBMaxAge: 24 * time.Hour, Timeout: 10 * time.Minute, Now: time.Now}
}

func (g *GrypeScanner) binary() string {
	if g.Binary == "" {
		return "grype"
	}
	return g.Binary
}

func (g *GrypeScanner) env() []string {
	return append(os.Environ(), "GRYPE_DB_CACHE_DIR="+g.DBDir, "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false")
}

// stampPath is the file that remembers when the database was last updated.
func (g *GrypeScanner) stampPath() string {
	return filepath.Join(g.DBDir, "updated")
}

// NeedsUpdate says the database is missing or older than DBMaxAge.
func (g *GrypeScanner) NeedsUpdate() bool {
	// 1. the stamp
	raw, err := os.ReadFile(g.stampPath())
	if err != nil {
		return true
	}
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return true
	}

	// 2. its age
	maxAge := g.DBMaxAge
	if maxAge == 0 {
		maxAge = 24 * time.Hour
	}
	return g.Now().Sub(at) > maxAge
}

// UpdateDB fetches the vulnerability database when it is missing or old, and
// writes the stamp.
func (g *GrypeScanner) UpdateDB(ctx context.Context) error {
	// 1. only when needed
	if !g.NeedsUpdate() {
		g.announce("grype: database current, %s", g.DBStatus(ctx))
		return nil
	}
	err := os.MkdirAll(g.DBDir, 0o755)
	if err != nil {
		return err
	}

	// 2. the update, a few hundred megabytes the first time
	g.announce("grype: updating the vulnerability database under %s, a few hundred megabytes the first time", g.DBDir)
	started := g.Now()
	ctx, cancel := context.WithTimeout(ctx, g.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, g.binary(), "db", "update")
	cmd.Env = g.env()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("grype db update: %v: %s", err, lastLines(output))
	}
	g.announce("grype: database updated in %s, %s", g.Now().Sub(started).Round(time.Second), g.DBStatus(ctx))

	// 3. the stamp
	return os.WriteFile(g.stampPath(), []byte(g.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// DBStatus asks grype what database it has, one line: what "grype db status"
// prints, joined. Empty when it cannot say.
func (g *GrypeScanner) DBStatus(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, g.binary(), "db", "status")
	cmd.Env = g.env()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "database status unknown"
	}
	var parts []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			parts = append(parts, strings.Join(strings.Fields(line), " "))
		}
	}
	return strings.Join(parts, ", ")
}

// Version asks the binary once what version it is, "unknown" when it cannot say:
// the JSON form first, the plain "Version: 0.118.0" line when JSON is refused.
func (g *GrypeScanner) Version(ctx context.Context) string {
	if g.version != "" {
		return g.version
	}

	// 1. the JSON form
	cmd := exec.CommandContext(ctx, g.binary(), "version", "-o", "json")
	cmd.Env = g.env()
	output, err := cmd.Output()
	if err == nil {
		g.version = parseVersion(output)
	}

	// 2. the plain form
	if g.version == "" {
		cmd = exec.CommandContext(ctx, g.binary(), "version")
		cmd.Env = g.env()
		output, err = cmd.Output()
		if err == nil {
			g.version = parseVersion(output)
		}
	}
	if g.version == "" {
		g.version = "unknown"
	}
	return g.version
}

// parseVersion reads grype's version from either output of "grype version":
// the JSON object with a "version" field, or the plain lines with "Version:".
func parseVersion(output []byte) string {
	// 1. JSON
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(output, &v) == nil && v.Version != "" {
		return v.Version
	}

	// 2. plain
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "Version" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (g *GrypeScanner) timeout() time.Duration {
	if g.Timeout == 0 {
		return 10 * time.Minute
	}
	return g.Timeout
}

// Scan runs grype on the CycloneDX file and returns one finding per CVE per
// component, the dev only advisories merged in.
func (g *GrypeScanner) Scan(ctx context.Context, cdxPath string, components []Component) ([]Finding, error) {
	// 1. the run
	ctx, cancel := context.WithTimeout(ctx, g.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, g.binary(), "sbom:"+cdxPath, "-o", "json")
	cmd.Env = g.env()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, errorf("grype: %v: %s", err, lastLines(stderr.Bytes()))
	}

	// 2. the matches
	findings, err := parseGrype(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	// 3. the dev only file, as if grype had found it
	dev, err := g.devFindings(components)
	if err != nil {
		return nil, err
	}
	return mergeFindings(findings, dev), nil
}

// grypeReport is the part of grype's JSON output the line manager reads.
type grypeReport struct {
	Matches []struct {
		Vulnerability grypeVulnerability   `json:"vulnerability"`
		Related       []grypeVulnerability `json:"relatedVulnerabilities"`
		Artifact      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"artifact"`
	} `json:"matches"`
}

// grypeVulnerability is one advisory record as grype writes it, the match's own
// (a GHSA record for a Maven package) or a related one (the CVE at NVD).
type grypeVulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	CVSS        []struct {
		Source  string `json:"source"`
		Version string `json:"version"`
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
	Fix struct {
		State string `json:"state"`
	} `json:"fix"`
	KnownExploited []struct {
		CVE string `json:"cve"`
	} `json:"knownExploited"`
	EPSS []struct {
		Percentile float64 `json:"percentile"`
	} `json:"epss"`
}

// parseGrype turns grype's JSON into findings, one per CVE per component.
func parseGrype(raw []byte) ([]Finding, error) {
	// 1. the report
	var rep grypeReport
	err := json.Unmarshal(raw, &rep)
	if err != nil {
		return nil, errorf("grype output: %w", err)
	}

	// 2. one finding per match
	var out []Finding
	seen := map[string]bool{}
	for _, m := range rep.Matches {
		c, ok := componentOfPURL(m.Artifact.PURL)
		if !ok {
			continue
		}
		f := grypeFinding(m.Vulnerability, m.Related, c)
		key := f.CVE + " " + c.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}

	// 3. a stable order
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		return out[i].Component.String() < out[j].Component.String()
	})
	return out, nil
}

// grypeFinding maps one match to a finding. The CVE id comes from the related
// records when the match is a GHSA; the score is NVD's 3.1 first, then any 3.1
// with its source named, then the floor of the severity word.
func grypeFinding(v grypeVulnerability, related []grypeVulnerability, c Component) Finding {
	f := Finding{Component: c, Summary: firstLine(v.Description)}

	// 1. the id: a CVE when the match is one, else the first related CVE, else the GHSA
	f.CVE = v.ID
	for _, r := range related {
		if r.ID != v.ID {
			f.Aliases = append(f.Aliases, r.ID)
		}
	}
	if !strings.HasPrefix(v.ID, "CVE-") {
		for _, r := range related {
			if strings.HasPrefix(r.ID, "CVE-") {
				f.CVE = r.ID
				break
			}
		}
	}

	// 2. the score: the related records first (the CVE as recorded at NVD), then the match's own
	records := append(append([]grypeVulnerability{}, related...), v)
	f.Score, f.CVSSSource = grypeScore(records, v.Severity)

	// 3. KEV, EPSS and the fix
	for _, r := range records {
		if len(r.KnownExploited) > 0 {
			f.KEV = true
		}
		if f.EPSSPercentile == nil && len(r.EPSS) > 0 {
			pct := r.EPSS[0].Percentile
			f.EPSSPercentile = &pct
		}
	}
	f.FixedByUpgrade = v.Fix.State == "fixed"
	return f
}

// grypeScore picks the score the rules read, the records in the order given: the
// CVSS 3.1 base score from nvd@nist.gov ("nvd"), else the first 3.1 found with its
// source named ("cna:<source>" as recorded at NVD, or "ghsa" for GitHub's own on
// the match record, which comes last), else the severity word's floor
// ("grype-word"), else nothing.
func grypeScore(records []grypeVulnerability, severity string) (*float64, string) {
	// 1. NVD's own 3.1
	for _, r := range records {
		for _, s := range r.CVSS {
			if s.Version == "3.1" && s.Source == "nvd@nist.gov" {
				score := s.Metrics.BaseScore
				return &score, "nvd"
			}
		}
	}

	// 2. any 3.1, the source named
	for _, r := range records {
		for _, s := range r.CVSS {
			if s.Version != "3.1" {
				continue
			}
			score := s.Metrics.BaseScore
			if s.Source == "" {
				return &score, "ghsa"
			}
			return &score, "cna:" + s.Source
		}
	}

	// 3. the word
	floor := wordFloor(severity)
	if floor == 0 {
		return nil, ""
	}
	return &floor, "grype-word"
}

// componentOfPURL reads pkg:maven/group/artifact@version, the purl a CycloneDX
// component carries; anything else is not a Maven coordinate and is skipped.
func componentOfPURL(purl string) (Component, bool) {
	// 1. the type
	rest, ok := strings.CutPrefix(purl, "pkg:maven/")
	if !ok {
		return Component{}, false
	}

	// 2. group/artifact@version, qualifiers dropped
	rest, _, _ = strings.Cut(rest, "?")
	path, version, ok := strings.Cut(rest, "@")
	if !ok {
		return Component{}, false
	}
	group, artifact, ok := strings.Cut(path, "/")
	if !ok {
		return Component{}, false
	}
	return Component{Group: group, Artifact: artifact, Version: version}, true
}

// devFindings turns the dev only file into findings for the components it
// affects, the score from the record's severity word, so a dev CVE is read
// the way grype would report it.
func (g *GrypeScanner) devFindings(components []Component) ([]Finding, error) {
	// 1. the records, by the same reader the sources use
	s := &Scanner{DevAdvisories: g.DevAdvisories}
	hits := map[string][]string{}
	records, err := s.devAdvisories(distinctComponents(components), hits)
	if err != nil {
		return nil, err
	}
	if g.DevAdvisories != "" {
		g.say("%s: %d dev advisory records read next to grype", g.DevAdvisories, len(records))
	}

	// 2. one finding per record per component
	var out []Finding
	for _, c := range distinctComponents(components) {
		for _, id := range hits[c.String()] {
			rec := records[id]
			f := Finding{CVE: canonicalID(id, rec.Aliases), Component: c, Summary: rec.Summary, Aliases: rec.Aliases, FixedByUpgrade: rec.fixedFor(c.Name())}
			floor := wordFloor(severityWord(rec))
			if floor > 0 {
				f.Score = &floor
				f.CVSSSource = "osv-word"
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// mergeFindings adds the second list to the first, a CVE on a component once.
func mergeFindings(first, second []Finding) []Finding {
	seen := map[string]bool{}
	for _, f := range first {
		seen[f.CVE+" "+f.Component.String()] = true
	}
	out := append([]Finding{}, first...)
	for _, f := range second {
		key := f.CVE + " " + f.Component.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		return out[i].Component.String() < out[j].Component.String()
	})
	return out
}

// lastLines keeps the tail of a tool's output for an error message.
func lastLines(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, " | ")
}
