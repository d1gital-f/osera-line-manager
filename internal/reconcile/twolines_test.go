// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/scan"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

const springLine = "spring-boot-2.7.x"

// Seen on the cluster on 14 Sept: a Spring entry with the same CVE on the same library as a
// dev entry, at another version, replaced the dev entry when Spring's statuses were put back.
// Another line's entry is never touched.
func TestReplaceEntriesLeavesOtherLinesAlone(t *testing.T) {
	p := &pass{staged: map[string][]byte{}}
	p.book = &book.Book{Entries: []book.Entry{
		{CVE: "CVE-2022-1471", Library: "org.yaml:snakeyaml", Version: "1.33", Lines: []string{testLine}, Status: book.EntryOpen},
		{CVE: "CVE-2022-1471", Library: "org.yaml:snakeyaml", Version: "1.30", Lines: []string{springLine}, Status: book.EntryOpen},
	}}
	r := &Reconciler{cfg: Config{LocalDir: t.TempDir()}, now: time.Now}
	fixed := []book.Entry{{CVE: "CVE-2022-1471", Library: "org.yaml:snakeyaml", Version: "1.30", Lines: []string{springLine}, Status: book.EntryFixed, FixedBy: "org.yaml:snakeyaml@1.30+osera-patch.001"}}
	r.replaceEntries(p, springLine, fixed)

	dev := p.book.ForLine(testLine)
	if len(dev) != 1 || dev[0].Version != "1.33" || dev[0].Status != book.EntryOpen {
		t.Fatalf("the dev entry was touched: %+v", p.book.Entries)
	}
	spring := p.book.ForLine(springLine)
	if len(spring) != 1 || spring[0].Status != book.EntryFixed {
		t.Fatalf("the spring entry was not replaced: %+v", spring)
	}
}

// A row never contradicts the backlog file: a record whose in scope differs from the file's
// entries for the line is logged and its row and status file are not written.
func TestRowGuard(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Join(book.LineColumns, ",") + "\n" + testLine + ",maven,org.example:bom@1.0,org.example@1.0,dev,a test,,,,,,,,,\n"
	if err := os.WriteFile(filepath.Join(dir, "supported-lines.csv"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{cfg: Config{LocalDir: dir}, now: time.Now}
	p := &pass{staged: map[string][]byte{}, book: &book.Book{Entries: []book.Entry{entry("CVE-2024-0001", "org.example:a", "1.0", book.EntryOpen)}}}
	p.records = []status.Record{{Line: testLine, Status: status.NotFixed, InScope: 5}}
	if err := r.stageOutputs(p); err != nil {
		t.Fatal(err)
	}
	if p.staged["supported-lines.csv"] != nil || p.staged["status/"+testLine+".json"] != nil {
		t.Fatalf("a contradicting row was staged: %v", p.staged)
	}
}

// Two passes on two lines sharing a CVE and a library. The first scans both and fails at the
// board: what it wrote is put back, no stamp is left, so the repository's own files stay as
// main has them. The second, with fresh stamps written by hand, keeps dev as the file has it,
// 3 in scope, and scans Spring again because the file carries no Spring entry at all: the
// result the failed pass lost is found again, 2 in scope, and dev is not touched by it.
func TestFailedPassLeavesTheFileAsItIs(t *testing.T) {
	// 1. the backlog repository: two lines, both graphs, the three dev entries, the rules
	o := newOrigin(t)
	o.write(t, "supported-lines.csv", strings.Join(book.LineColumns, ",")+"\n"+
		springLine+",maven,org.example:bom@1.0,org.example@1.0,wave-1,a test,,,,,,,,,\n"+
		testLine+",maven,org.example:bom@1.0,org.example@1.0,dev,a test,,,,,,,,,\n")
	anchor := book.Anchor{Group: "org.example", Artifact: "bom", Version: "1.0"}
	writeGraph(t, o.dir, book.Line{ID: springLine, Anchor: "org.example:bom@1.0", Components: []string{"org.example@1.0"}}, anchor)
	writeGraph(t, o.dir, book.Line{ID: testLine, Anchor: "org.example:bom@1.0", Components: []string{"org.example@1.0"}}, anchor)
	devEntries := []book.Entry{
		entry("CVE-2022-1471", "org.yaml:snakeyaml", "1.33", book.EntryOpen),
		entry("CVE-2025-52999", "com.fasterxml.jackson.core:jackson-core", "2.14.2", book.EntryOpen),
		entry("GHSA-r7wm-3cxj-wff9", "com.fasterxml.jackson.core:jackson-core", "2.14.2", book.EntryOpen),
	}
	backlog := map[string]any{"schema_version": "0.6.0", "title": "test backlog", "standards_pack": "OSERA-SP-0.1.0", "generated": "2026-10-01T00:00:00Z", "entry_schema": "cve-backlog-entry-0.6.0.schema.json", "entries": devEntries}
	raw, _ := json.MarshalIndent(backlog, "", " ")
	o.write(t, "cve-backlog.json", string(raw))
	rulesFile, err := os.ReadFile("testdata/prioritisation.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o.write(t, "rules/prioritisation.yaml", string(rulesFile))
	o.repo.CreateTag("v2026.10.01", o.commit(t, "the test backlog"), nil)
	committed, _ := os.ReadFile(filepath.Join(o.dir, "cve-backlog.json"))

	// 2. a GitHub whose board answers 401 the first time, as an expired token does
	calls := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"token": "ghs_test", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"data":{"organization":{"projectV2":{"items":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[]}}}}}`))
		default:
			t.Errorf("unexpected GitHub call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer gh.Close()
	nx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":[],"continuationToken":null}`))
	}))
	defer nx.Close()

	// 3. the reconciler with a scan that finds the same CVEs on Spring at other versions
	cache := t.TempDir()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	cfg := Config{
		Scanner: "sources",
		Owner:   "dev-finos-osera-forks", Repo: "backlog", CloneDir: filepath.Join(t.TempDir(), "clone"),
		App:         AppConfig{ID: 1, InstallationID: 2, KeyFile: keyFile(t)},
		BoardNumber: 1,
		Nexus:       NexusConfig{URL: nx.URL, User: "line-manager", Password: "pw", ReleaseRepository: "osera-releases-maven-01"},
		CacheDir:    cache, Interval: time.Minute, RescanInterval: 7 * 24 * time.Hour,
		RepoURL: o.dir, GitHubAPI: gh.URL, GraphQLURL: gh.URL + "/graphql",
		Now: func() time.Time { return now },
	}
	r, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	score := 9.8
	r.scanFn = func(ctx context.Context, lineID string, components []scan.Component) ([]scan.Finding, error) {
		if lineID == springLine {
			return []scan.Finding{
				{CVE: "CVE-2022-1471", Component: scan.Component{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.30"}, Score: &score, CVSSSource: "nvd"},
				{CVE: "CVE-2025-52999", Component: scan.Component{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.13.5"}, Score: &score, CVSSSource: "nvd"},
			}, nil
		}
		return []scan.Finding{
			{CVE: "CVE-2022-1471", Component: scan.Component{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"}, Score: &score, CVSSSource: "nvd"},
			{CVE: "CVE-2025-52999", Component: scan.Component{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.14.2"}, Score: &score, CVSSSource: "nvd"},
			{CVE: "GHSA-r7wm-3cxj-wff9", Component: scan.Component{Group: "com.fasterxml.jackson.core", Artifact: "jackson-core", Version: "2.14.2"}, Score: &score, CVSSSource: "nvd"},
		}, nil
	}

	// 4. pass A: both scanned, then the board fails
	_, err = r.Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("pass A should fail at the board: %v", err)
	}
	onDisk, _ := os.ReadFile(filepath.Join(cfg.CloneDir, "cve-backlog.json"))
	if string(onDisk) != string(committed) {
		t.Fatalf("the failed pass left its backlog in the worktree:\n%s", onDisk)
	}
	for _, line := range []string{springLine, testLine} {
		if _, statErr := os.Stat(r.scanStamp(line)); statErr == nil {
			t.Fatalf("a stamp was written by the failed pass for %s", line)
		}
	}

	// 5. pass B with fresh stamps: no scan, the file as it is
	for _, line := range []string{springLine, testLine} {
		os.WriteFile(r.scanStamp(line), []byte(now.Add(-time.Hour).Format(time.RFC3339)+"\n"), 0o644)
	}
	r.cfg.Dry = true
	records, err := r.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byLine := map[string]status.Record{}
	for _, rec := range records {
		byLine[rec.Line] = rec
	}
	if byLine[testLine].InScope != 3 || byLine[springLine].InScope != 2 {
		t.Fatalf("dev in scope %d, spring in scope %d", byLine[testLine].InScope, byLine[springLine].InScope)
	}
	if len(byLine[testLine].Open) != 3 || byLine[testLine].Status != status.NotFixed {
		t.Fatalf("dev record %+v", byLine[testLine])
	}
}
