// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/rules"
)

// The rules as the dev backlog publishes them, enough for Apply.
const rulesYAML = `version: 0.1.0
bands: {critical: 9.0, high: 7.0, medium: 4.0}
signals: {epss_percentile: 0.90, kev: true, member_exploit_evidence: true, on_runtime_path_and_listed: true, fixed_by_upgrade: true}
include:
  - {rule: critical, when: band == critical}
  - {rule: high, when: band == high}
  - {rule: kev, when: kev}
  - {rule: medium-signal, when: score >= 6.0 and score < 7.0 and any signal}
priority:
  - P0 / Act: kev or (band == critical and (epss signal or member exploit evidence))
  - P1 / Attend: score >= 7.0
  - P2 / Investigate: score >= 6.0 and score < 7.0 and any signal
  - P3 / Track: score >= 6.0 and score < 7.0
  - P4 / Exclude: otherwise
curated_list:
  groups: [org.yaml]
  prefixes: [com.fasterxml.jackson]
`

// sources is a fake of the four public sources, counting every request.
type sources struct {
	server   *httptest.Server
	requests atomic.Int64
}

func fakeSources(t *testing.T) *sources {
	t.Helper()
	s := &sources{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /osv/querybatch", func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		var q struct {
			Queries []struct {
				Version string `json:"version"`
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		var results []map[string]any
		for _, x := range q.Queries {
			switch x.Package.Name + "@" + x.Version {
			case "com.fasterxml.jackson.core:jackson-core@2.14.2":
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-h46c-h94v-95w3"}}})
			case "org.yaml:snakeyaml@1.33":
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "CVE-2022-1471"}, {"id": "GHSA-mjmj-j48q-9wg2"}}})
			case "org.bouncycastle:bcprov-jdk18on@1.70":
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "CVE-2023-33201"}}})
			default:
				results = append(results, map[string]any{})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /osv/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		id := r.PathValue("id")
		records := map[string]map[string]any{
			"GHSA-h46c-h94v-95w3": {"id": "GHSA-h46c-h94v-95w3", "aliases": []string{"CVE-2025-52999"}, "summary": "jackson-core: deep nesting", "database_specific": map[string]string{"severity": "HIGH"},
				"affected": []map[string]any{{"package": map[string]string{"name": "com.fasterxml.jackson.core:jackson-core", "ecosystem": "Maven"}, "ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "2.15.0"}}}}}}},
			"CVE-2022-1471":       {"id": "CVE-2022-1471", "aliases": []string{"GHSA-mjmj-j48q-9wg2"}, "summary": "snakeyaml: constructor deserialization", "database_specific": map[string]string{"severity": "CRITICAL"}},
			"GHSA-mjmj-j48q-9wg2": {"id": "GHSA-mjmj-j48q-9wg2", "aliases": []string{"CVE-2022-1471"}, "summary": "snakeyaml: constructor deserialization", "database_specific": map[string]string{"severity": "CRITICAL"}},
			"CVE-2023-33201":      {"id": "CVE-2023-33201", "details": "Bouncy Castle: LDAP injection\nmore text", "database_specific": map[string]string{"severity": "MODERATE"}},
		}
		rec, known := records[id]
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
	})
	mux.HandleFunc("GET /kev", func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []map[string]string{{"cveID": "CVE-2022-1471"}}})
	})
	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		var data []map[string]string
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			switch cve {
			case "CVE-2022-1471":
				data = append(data, map[string]string{"cve": cve, "epss": "0.5", "percentile": "0.97"})
			case "CVE-2025-52999":
				data = append(data, map[string]string{"cve": cve, "epss": "0.001", "percentile": "0.12"})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	mux.HandleFunc("GET /nvd", func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		metric := func(source, typ string, score float64) map[string]any {
			return map[string]any{"source": source, "type": typ, "cvssData": map[string]any{"baseScore": score}}
		}
		var metrics map[string]any
		switch r.URL.Query().Get("cveId") {
		case "CVE-2022-1471":
			metrics = map[string]any{"cvssMetricV31": []map[string]any{metric("cna@example", "Secondary", 8.3), metric("nvd@nist.gov", "Primary", 9.8)}}
		case "CVE-2025-52999":
			metrics = map[string]any{"cvssMetricV31": []map[string]any{metric("cna@example", "Secondary", 7.5)}}
		case "CVE-2023-33201":
			metrics = map[string]any{"cvssMetricV31": []map[string]any{metric("nvd@nist.gov", "Primary", 5.3)}}
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []map[string]any{{"cve": map[string]any{"vulnStatus": "Analyzed", "metrics": metrics}}}})
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func scanner(t *testing.T, s *sources, cacheDir string) *Scanner {
	t.Helper()
	sc := New(cacheDir)
	sc.HTTP = s.server.Client()
	sc.OSVURL = s.server.URL + "/osv"
	sc.KEVURL = s.server.URL + "/kev"
	sc.EPSSURL = s.server.URL + "/epss"
	sc.NVDURL = s.server.URL + "/nvd"
	sc.NVDAPIKey = ""
	sc.NVDPause = 0
	return sc
}

var components = []Component{
	{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.14.2"},
	{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"},
	{Group: "org.bouncycastle", Artifact: "bcprov-jdk18on", Version: "1.70"},
	{Group: "commons-io", Artifact: "commons-io", Version: "2.11.0"},
	{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"},
}

// 1. Every source read, one finding per CVE per component, scores from the right place.
func TestScan(t *testing.T) {
	src := fakeSources(t)
	sc := scanner(t, src, t.TempDir())
	findings, err := sc.Scan(context.Background(), components)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings %d, want 3: %v", len(findings), findings)
	}
	byCVE := map[string]Finding{}
	for _, f := range findings {
		byCVE[f.CVE] = f
	}
	snake := byCVE["CVE-2022-1471"]
	if snake.Score == nil || *snake.Score != 9.8 || snake.CVSSSource != "nvd" || !snake.KEV || snake.EPSSPercentile == nil || *snake.EPSSPercentile != 0.97 {
		t.Fatalf("snakeyaml finding %+v", snake)
	}
	jackson := byCVE["CVE-2025-52999"]
	if jackson.Score == nil || *jackson.Score != 7.5 || jackson.CVSSSource != "cna" || jackson.KEV || !jackson.FixedByUpgrade || jackson.Component.Version != "2.14.2" {
		t.Fatalf("jackson finding %+v", jackson)
	}
	bc := byCVE["CVE-2023-33201"]
	if bc.Score == nil || *bc.Score != 5.3 || bc.Summary != "Bouncy Castle: LDAP injection" {
		t.Fatalf("bouncy castle finding %+v", bc)
	}
}

// 2. A second pass reads the records, EPSS and NVD from the cache: only the batch and the KEV list are asked again, and KEV only when stale.
func TestCache(t *testing.T) {
	src := fakeSources(t)
	dir := t.TempDir()
	sc := scanner(t, src, dir)
	_, err := sc.Scan(context.Background(), components)
	if err != nil {
		t.Fatal(err)
	}
	first := src.requests.Load()
	for _, name := range []string{"osv-records.json", "kev.json", "epss.json", "nvd.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("cache file %s: %v", name, err)
		}
	}
	src.requests.Store(0)
	_, err = sc.Scan(context.Background(), components)
	if err != nil {
		t.Fatal(err)
	}
	second := src.requests.Load()
	if second != 1 {
		t.Fatalf("second pass made %d requests, want 1 (the batch); first pass made %d", second, first)
	}
	// 3. a day later the KEV list is read again
	sc.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	src.requests.Store(0)
	_, err = sc.Scan(context.Background(), components)
	if err != nil {
		t.Fatal(err)
	}
	if src.requests.Load() != 2 {
		t.Fatalf("stale KEV pass made %d requests, want 2", src.requests.Load())
	}
}

// 3. A dev only record applies by listed version and by range, and is scored like any other.
func TestDevAdvisories(t *testing.T) {
	src := fakeSources(t)
	sc := scanner(t, src, t.TempDir())
	dev := filepath.Join(t.TempDir(), "dev.json")
	err := os.WriteFile(dev, []byte(`{"source": "test", "vulns": [
	 {"id": "CVE-2099-0001", "summary": "invented on commons-io", "database_specific": {"severity": "CRITICAL"},
	  "affected": [{"package": {"name": "commons-io:commons-io", "ecosystem": "Maven"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.12.0"}]}]}]},
	 {"id": "CVE-2099-0002", "summary": "invented on snakeyaml by version", "database_specific": {"severity": "LOW"},
	  "affected": [{"package": {"name": "org.yaml:snakeyaml", "ecosystem": "Maven"}, "versions": ["1.33"]}]},
	 {"id": "CVE-2099-0003", "summary": "does not apply, fixed before", "database_specific": {"severity": "HIGH"},
	  "affected": [{"package": {"name": "commons-io:commons-io", "ecosystem": "Maven"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.7"}]}]}]}
	]}`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	sc.DevAdvisories = dev
	findings, err := sc.Scan(context.Background(), components)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Finding{}
	for _, f := range findings {
		got[f.CVE] = f
	}
	if _, found := got["CVE-2099-0003"]; found {
		t.Fatalf("CVE-2099-0003 applied to 2.11.0, fixed in 2.7")
	}
	one := got["CVE-2099-0001"]
	if one.Component.Artifact != "commons-io" || one.Score == nil || *one.Score != 9.0 || one.CVSSSource != "osv-word" || !one.FixedByUpgrade {
		t.Fatalf("CVE-2099-0001 %+v", one)
	}
	two := got["CVE-2099-0002"]
	if two.Component.Artifact != "snakeyaml" || two.Score == nil || *two.Score != 0.1 {
		t.Fatalf("CVE-2099-0002 %+v", two)
	}
	if len(findings) != 5 {
		t.Fatalf("findings %d, want 5", len(findings))
	}
}

// 4. The version comparison, the stand in.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.11.0", "2.12.0", -1},
		{"2.12.0", "2.11.0", 1},
		{"2.7", "2.11.0", -1},
		{"1.33", "1.33", 0},
		{"5.3.39", "5.3.39.1", -1},
		{"9.0.83", "9.0.9", 1},
		{"1.0.0-beta", "1.0.0", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare %s %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// 5. Apply: in, and out for each reason.
func TestApply(t *testing.T) {
	r, err := rules.Parse([]byte(rulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	f := func(score float64) *float64 { return &score }
	p := func(pct float64) *float64 { return &pct }
	jackson := Component{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.14.2"}
	snake := Component{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"}
	bc := Component{Group: "org.bouncycastle", Artifact: "bcprov-jdk18on", Version: "1.70"}
	findings := []Finding{
		{CVE: "CVE-2022-1471", Component: snake, Score: f(9.8), CVSSSource: "nvd", KEV: true, EPSSPercentile: p(0.97), Summary: "snakeyaml"},
		{CVE: "CVE-2025-52999", Component: jackson, Score: f(7.5), CVSSSource: "cna", EPSSPercentile: p(0.12), Summary: "jackson", FixedByUpgrade: true},
		{CVE: "CVE-2023-33201", Component: bc, Score: f(9.1), CVSSSource: "nvd", Summary: "off the list"},
		{CVE: "CVE-2099-0010", Component: jackson, Score: f(6.4), CVSSSource: "nvd", Summary: "window, no signal"},
		{CVE: "CVE-2099-0011", Component: jackson, Score: f(6.4), CVSSSource: "nvd", EPSSPercentile: p(0.95), Summary: "window with epss"},
		{CVE: "CVE-2099-0012", Component: jackson, Score: f(5.3), CVSSSource: "nvd", Summary: "below"},
		{CVE: "CVE-2099-0013", Component: jackson, Summary: "unscored"},
		{CVE: "CVE-2099-0014", Component: jackson, Score: f(4.0), CVSSSource: "nvd", KEV: true, Summary: "kev on a medium"},
	}
	out := Apply("dev-1.0.x", findings, r)
	// on the curated list and on the runtime path is itself a signal (rule 2d), so the
	// 6.4 without EPSS is in as well, after the one with EPSS
	if len(out.Entries) != 5 {
		t.Fatalf("entries %d, want 5: %+v", len(out.Entries), out.Entries)
	}
	// 1. the order: KEV first, then priority, then score, then EPSS
	want := []string{"CVE-2022-1471", "CVE-2099-0014", "CVE-2025-52999", "CVE-2099-0011", "CVE-2099-0010"}
	for i, e := range out.Entries {
		if e.CVE != want[i] {
			t.Fatalf("entry %d is %s, want %s", i, e.CVE, want[i])
		}
		if e.Status != "open" || len(e.Lines) != 1 || e.Lines[0] != "dev-1.0.x" {
			t.Fatalf("entry %+v", e)
		}
	}
	// 2. the why of the first: the rule, then the signals
	first := out.Entries[0]
	if first.Priority != "P0 / Act" || first.Why[0] != whyRule["critical"] || first.Why[1] != "listed in CISA KEV" {
		t.Fatalf("first entry why %v priority %s", first.Why, first.Priority)
	}
	// 3. the excluded, one reason each
	reasons := map[string]string{}
	for _, x := range out.Excluded {
		reasons[x.CVE] = x.Reason
	}
	wantReasons := map[string]string{
		"CVE-2023-33201": "group org.bouncycastle is not on the curated list",
		"CVE-2099-0012":  "score 5.3, below the 6.0 to 6.9 window and not on the KEV list",
		"CVE-2099-0013":  "unscored, not on the KEV list",
	}
	if len(reasons) != len(wantReasons) {
		t.Fatalf("excluded %v", reasons)
	}
	for cve, reason := range wantReasons {
		if reasons[cve] != reason {
			t.Errorf("%s reason %q, want %q", cve, reasons[cve], reason)
		}
	}
}

// 6. The two files: valid JSON, the header, the order kept.
func TestWrite(t *testing.T) {
	r, err := rules.Parse([]byte(rulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	f := func(score float64) *float64 { return &score }
	jackson := Component{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.14.2"}
	out := Apply("dev-1.0.x", []Finding{
		{CVE: "CVE-2099-0002", Component: jackson, Score: f(7.1), CVSSSource: "nvd"},
		{CVE: "CVE-2099-0001", Component: jackson, Score: f(9.1), CVSSSource: "nvd"},
		{CVE: "CVE-2099-0003", Component: jackson, Score: f(2.0), CVSSSource: "nvd"},
	}, r)
	dir := t.TempDir()
	h := Header{Title: "test", StandardsPack: "OSERA-SP-0.1.0", Generated: "2026-09-14"}
	if err := WriteBacklog(filepath.Join(dir, "cve-backlog.json"), h, out.Entries); err != nil {
		t.Fatal(err)
	}
	if err := WriteExcluded(filepath.Join(dir, "cve-excluded.json"), h, out.Excluded); err != nil {
		t.Fatal(err)
	}
	var backlog struct {
		SchemaVersion string `json:"schema_version"`
		EntrySchema   string `json:"entry_schema"`
		Entries       []struct {
			CVE    string `json:"cve"`
			Status string `json:"status"`
		} `json:"entries"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "cve-backlog.json"))
	if err := json.Unmarshal(raw, &backlog); err != nil {
		t.Fatal(err)
	}
	if backlog.SchemaVersion != "0.6.0" || backlog.EntrySchema != "cve-backlog-entry-0.6.0.schema.json" || len(backlog.Entries) != 2 {
		t.Fatalf("backlog header %+v", backlog)
	}
	if backlog.Entries[0].CVE != "CVE-2099-0001" || backlog.Entries[1].CVE != "CVE-2099-0002" || backlog.Entries[0].Status != "open" {
		t.Fatalf("backlog order %+v", backlog.Entries)
	}
	var excluded struct {
		Entries []struct {
			CVE    string `json:"cve"`
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "cve-excluded.json"))
	if err := json.Unmarshal(raw, &excluded); err != nil {
		t.Fatal(err)
	}
	if len(excluded.Entries) != 1 || excluded.Entries[0].CVE != "CVE-2099-0003" || excluded.Entries[0].Reason == "" {
		t.Fatalf("excluded %+v", excluded.Entries)
	}
}

// 7. With the graph signal switched off in the rules, a 6.4 without any other signal is out, with the window reason.
func TestWindowWithoutSignal(t *testing.T) {
	r, err := rules.Parse([]byte(strings.Replace(rulesYAML, "on_runtime_path_and_listed: true", "on_runtime_path_and_listed: false", 1)))
	if err != nil {
		t.Fatal(err)
	}
	score := 6.4
	jackson := Component{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.14.2"}
	out := Apply("dev-1.0.x", []Finding{{CVE: "CVE-2099-0010", Component: jackson, Score: &score, CVSSSource: "nvd"}}, r)
	if len(out.Entries) != 0 || len(out.Excluded) != 1 || out.Excluded[0].Reason != "score 6.4, no signal in the 6.0 to 6.9 window" {
		t.Fatalf("entries %d excluded %+v", len(out.Entries), out.Excluded)
	}
}

// Two findings of one CVE on one library at two versions fold onto the higher version,
// named in words; findings on other libraries or other CVEs are untouched.
func TestOnePerLibrary(t *testing.T) {
	seven := 7.0
	f := []Finding{
		{CVE: "CVE-1", Component: Component{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.31"}, Score: &seven},
		{CVE: "CVE-1", Component: Component{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.39"}, Score: &seven},
		{CVE: "CVE-2", Component: Component{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.39"}, Score: &seven},
		{CVE: "CVE-1", Component: Component{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"}, Score: &seven},
	}
	kept, folded := onePerLibrary(f)
	if len(kept) != 3 || kept[0].Component.Version != "5.3.39" || kept[1].CVE != "CVE-2" || kept[2].Component.Artifact != "snakeyaml" {
		t.Fatalf("kept %v", kept)
	}
	if len(folded) != 1 || folded[0] != "CVE-1 on org.springframework:spring-core@5.3.31 folded onto org.springframework:spring-core@5.3.39" {
		t.Fatalf("folded %v", folded)
	}
}
