// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/rules"
)

// The saved output of grype 0.118.0 on the dev line's graph, 14 Sept 2026.
func grypeDev(t *testing.T) []Finding {
	raw, err := os.ReadFile("testdata/grype-dev-1.0.x.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := parseGrype(raw)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// 1. Six matches, six findings, one per CVE per component, sorted.
func TestParseGrype(t *testing.T) {
	findings := grypeDev(t)
	if len(findings) != 6 {
		t.Fatalf("findings %d, want 6: %v", len(findings), findings)
	}
	want := []string{"CVE-2022-1471", "CVE-2022-25647", "CVE-2024-47554", "CVE-2025-48924", "CVE-2025-52999", "GHSA-r7wm-3cxj-wff9"}
	for i, f := range findings {
		if f.CVE != want[i] {
			t.Fatalf("finding %d is %s, want %s", i, f.CVE, want[i])
		}
	}
}

// 2. One finding field by field: snakeyaml, NVD's 3.1 over GitHub's, the GHSA as alias, EPSS, the fix.
func TestGrypeFindingFields(t *testing.T) {
	var snake Finding
	for _, f := range grypeDev(t) {
		if f.CVE == "CVE-2022-1471" {
			snake = f
		}
	}
	if snake.Component.String() != "org.yaml:snakeyaml@1.33" {
		t.Fatalf("component %s", snake.Component)
	}
	if snake.Score == nil || *snake.Score != 9.8 || snake.CVSSSource != "nvd" {
		t.Fatalf("score %v source %q, want 9.8 nvd", snake.Score, snake.CVSSSource)
	}
	if len(snake.Aliases) != 1 || snake.Aliases[0] != "CVE-2022-1471" {
		// the match is the GHSA, the related record is the CVE: the CVE became the id, the alias list carries the related id
		t.Fatalf("aliases %v", snake.Aliases)
	}
	if snake.EPSSPercentile == nil || *snake.EPSSPercentile < 0.99 {
		t.Fatalf("epss %v", snake.EPSSPercentile)
	}
	if !snake.FixedByUpgrade {
		t.Fatal("fix state fixed not read")
	}
	if snake.KEV {
		t.Fatal("KEV true with no knownExploited list")
	}
	if snake.Summary == "" {
		t.Fatal("no summary")
	}
}

// 3. The score rule: a 3.1 from a CNA is named, a record with only a 4.0 falls to the severity word.
func TestGrypeScoreRule(t *testing.T) {
	by := map[string]Finding{}
	for _, f := range grypeDev(t) {
		by[f.CVE] = f
	}
	// commons-io: NVD carries a CNA's 3.1 of 4.3 and no analysis of its own; GitHub's own record says 7.5
	io := by["CVE-2024-47554"]
	if io.Score == nil || *io.Score != 4.3 || io.CVSSSource != "cna:134c704f-9b21-4f2e-91b3-4a467353bcc0" {
		t.Fatalf("commons-io score %v source %q, want 4.3 from the CNA as recorded at NVD", io.Score, io.CVSSSource)
	}
	// jackson-core CVE-2025-52999: only 4.0 scores anywhere, the word High gives 7.0
	jackson := by["CVE-2025-52999"]
	if jackson.Score == nil || *jackson.Score != 7.0 || jackson.CVSSSource != "grype-word" {
		t.Fatalf("jackson score %v source %q", jackson.Score, jackson.CVSSSource)
	}
	// the GHSA with no CVE keeps its GHSA id
	if _, found := by["GHSA-r7wm-3cxj-wff9"]; !found {
		t.Fatal("GHSA without a CVE lost")
	}
}

// 4. KEV and EPSS mapping on a hand made record.
func TestGrypeKEVAndEPSS(t *testing.T) {
	v := grypeVulnerability{ID: "GHSA-test-test-test", Severity: "Critical"}
	v.KnownExploited = append(v.KnownExploited, struct {
		CVE string `json:"cve"`
	}{CVE: "CVE-2099-0001"})
	v.EPSS = append(v.EPSS, struct {
		Percentile float64 `json:"percentile"`
	}{Percentile: 0.97})
	related := []grypeVulnerability{{ID: "CVE-2099-0001"}}
	f := grypeFinding(v, related, Component{Group: "g", Artifact: "a", Version: "1"})
	if f.CVE != "CVE-2099-0001" || !f.KEV || f.EPSSPercentile == nil || *f.EPSSPercentile != 0.97 {
		t.Fatalf("finding %+v", f)
	}
	if f.Score == nil || *f.Score != 9.0 || f.CVSSSource != "grype-word" {
		t.Fatalf("score %v %q", f.Score, f.CVSSSource)
	}
}

// 5. The database stamp: missing, fresh, old.
func TestGrypeNeedsUpdate(t *testing.T) {
	dir := t.TempDir()
	g := NewGrype("grype", dir)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	g.Now = func() time.Time { return now }
	if !g.NeedsUpdate() {
		t.Fatal("no stamp, no update")
	}
	err := os.WriteFile(filepath.Join(dir, "updated"), []byte(now.Add(-2*time.Hour).Format(time.RFC3339)+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if g.NeedsUpdate() {
		t.Fatal("two hours old, update wanted")
	}
	err = os.WriteFile(filepath.Join(dir, "updated"), []byte(now.Add(-30*time.Hour).Format(time.RFC3339)+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if !g.NeedsUpdate() {
		t.Fatal("thirty hours old, no update")
	}
}

// 6. The purl reader.
func TestComponentOfPURL(t *testing.T) {
	c, ok := componentOfPURL("pkg:maven/org.yaml/snakeyaml@1.33?type=jar")
	if !ok || c.String() != "org.yaml:snakeyaml@1.33" {
		t.Fatalf("%v %v", c, ok)
	}
	if _, ok := componentOfPURL("pkg:npm/lodash@4.17.21"); ok {
		t.Fatal("npm read as maven")
	}
}

// 7. The rules on grype's findings give the dev line's split of 14 Sept: three in, three out by the curated list.
func TestApplyOnGrype(t *testing.T) {
	r, err := rules.Parse([]byte(rulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	out := Apply("dev-1.0.x", grypeDev(t), r)
	if len(out.Entries) != 3 || len(out.Excluded) != 3 {
		t.Fatalf("entries %d excluded %d", len(out.Entries), len(out.Excluded))
	}
	if out.Entries[0].CVE != "CVE-2022-1471" || out.Entries[0].Priority != "P0 / Act" || out.Entries[0].CVSS != 9.8 {
		t.Fatalf("first entry %+v", out.Entries[0])
	}
	for _, x := range out.Excluded {
		if x.Reason != "group com.google.code.gson is not on the curated list" && x.Reason != "group commons-io is not on the curated list" && x.Reason != "group org.apache.commons is not on the curated list" {
			t.Fatalf("reason %q", x.Reason)
		}
	}
}

// 8. The dev only file merged into grype's findings, once per CVE and component.
func TestGrypeDevAdvisories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.json")
	err := os.WriteFile(path, []byte(`{"vulns":[{"id":"CVE-2099-0001","summary":"invented","affected":[{"package":{"name":"org.yaml:snakeyaml","ecosystem":"Maven"},"versions":["1.33"]}],"database_specific":{"severity":"HIGH"}}]}`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGrype("grype", dir)
	g.DevAdvisories = path
	dev, err := g.devFindings([]Component{{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(dev) != 1 || dev[0].CVE != "CVE-2099-0001" || dev[0].Score == nil || *dev[0].Score != 7.0 {
		t.Fatalf("dev findings %+v", dev)
	}
	merged := mergeFindings(grypeDev(t), dev)
	if len(merged) != 7 {
		t.Fatalf("merged %d, want 7", len(merged))
	}
}

// The version is read from either form of "grype version"; "-o raw" is not a form grype has.
func TestParseVersion(t *testing.T) {
	asJSON := []byte("{\n \"application\": \"grype\",\n \"buildDate\": \"2026-08-27T18:40:29Z\",\n \"supportedDbSchema\": 6,\n \"syftVersion\": \"v1.51.1\",\n \"version\": \"0.118.0\"\n}\n")
	plain := []byte("Application:         grype\nVersion:             0.118.0\nBuildDate:           2026-08-27T18:40:29Z\nGitCommit:           Homebrew\n")
	if got := parseVersion(asJSON); got != "0.118.0" {
		t.Fatalf("json: %q", got)
	}
	if got := parseVersion(plain); got != "0.118.0" {
		t.Fatalf("plain: %q", got)
	}
	if got := parseVersion([]byte("unsupported output format: raw")); got != "" {
		t.Fatalf("garbage: %q", got)
	}
}
