// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/d1gital-f/osera-line-manager/internal/bom"
	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/graph"
	"github.com/d1gital-f/osera-line-manager/internal/intent"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

const testLine = "dev-1.0.x"

func entry(cve, library, version, st string) book.Entry {
	return book.Entry{CVE: cve, Library: library, Version: version, Lines: []string{testLine}, CVSS: 9.8, CVSSVersion: "3.1", Priority: "P0 / Act", Why: []string{"Rule 1: include all Critical CVEs, CVSS >= 9.0"}, Summary: "a summary", Status: st}
}

// 1. A scan merged into the backlog keeps the statuses, refreshes the facts, adds the new ones open.
func TestMergeScan(t *testing.T) {
	existing := []book.Entry{
		entry("CVE-2024-0001", "org.example:a", "1.0", book.EntryFixed),
		entry("CVE-2024-0002", "org.example:b", "1.0", book.EntryInProgress),
	}
	existing[0].FixedBy = "org.example:a@1.0+osera-patch.001"
	rescanned := entry("CVE-2024-0001", "org.example:a", "1.0", book.EntryOpen)
	rescanned.CISAKEV = true
	newOne := entry("CVE-2024-0003", "org.example:c", "2.0", "")
	out := mergeScan(existing, testLine, []book.Entry{rescanned, newOne})
	if len(out) != 3 {
		t.Fatalf("entries %d, want 3", len(out))
	}
	if out[0].Status != book.EntryFixed || out[0].FixedBy == "" || !out[0].CISAKEV {
		t.Fatalf("the fixed entry should keep its status and take the new fact: %+v", out[0])
	}
	if out[1].Status != book.EntryInProgress {
		t.Fatalf("the entry the scan did not find should stay: %+v", out[1])
	}
	if out[2].CVE != "CVE-2024-0003" || out[2].Status != book.EntryOpen {
		t.Fatalf("the new entry should be open: %+v", out[2])
	}
}

// 2. The graph is built when missing or from another anchor, kept when present.
func TestNeedsGraph(t *testing.T) {
	dir := t.TempDir()
	ln := book.Line{ID: testLine, Anchor: "org.example:bom@1.0"}
	needed, err := needsGraph(dir, ln)
	if err != nil || !needed {
		t.Fatalf("missing: needed %v err %v", needed, err)
	}
	writeGraph(t, dir, ln, book.Anchor{Group: "org.example", Artifact: "bom", Version: "0.9"})
	needed, err = needsGraph(dir, ln)
	if err != nil || !needed {
		t.Fatalf("other anchor: needed %v err %v", needed, err)
	}
	writeGraph(t, dir, ln, book.Anchor{Group: "org.example", Artifact: "bom", Version: "1.0"})
	needed, err = needsGraph(dir, ln)
	if err != nil || needed {
		t.Fatalf("present: needed %v err %v", needed, err)
	}

	// the line gains components: the roots rule changes, the wide graph is rebuilt narrow
	ln.Components = []string{"org.example:a@1.0"}
	needed, err = needsGraph(dir, ln)
	if err != nil || !needed {
		t.Fatalf("other roots rule: needed %v err %v", needed, err)
	}
}

func writeGraph(t *testing.T, dir string, ln book.Line, anchor book.Anchor) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(graphPath(ln.ID)))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	g := &graph.Graph{LineID: ln.ID, Anchor: anchor, RootsRule: graph.RuleFor(anchor, ln.Components).String(), Components: []graph.Component{{Group: "org.example", Artifact: "a", Version: "1.0"}}, Dependencies: map[string][]string{}}
	if err := graph.Write(path, g, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// 3. The scan runs when never done, when old, when the graph is new; not when fresh.
func TestNeedsScan(t *testing.T) {
	stamp := filepath.Join(t.TempDir(), "stamp")
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	week := 7 * 24 * time.Hour
	if !needsScan(stamp, false, true, week, now) {
		t.Fatal("never scanned should scan")
	}
	os.WriteFile(stamp, []byte(now.Add(-8*24*time.Hour).Format(time.RFC3339)), 0o644)
	if !needsScan(stamp, false, true, week, now) {
		t.Fatal("older than the interval should scan")
	}
	os.WriteFile(stamp, []byte(now.Add(-time.Hour).Format(time.RFC3339)), 0o644)
	if needsScan(stamp, false, true, week, now) {
		t.Fatal("fresh should not scan")
	}
	if !needsScan(stamp, true, true, week, now) {
		t.Fatal("a new graph should scan")
	}
	if !needsScan(stamp, false, false, week, now) {
		t.Fatal("a line with no entries should scan")
	}
}

// 4. A BOM is due when the promoted set moved, not when it is the same, never with nothing fixed.
func TestNeedsBOM(t *testing.T) {
	pins := []bom.Dependency{{Group: "org.example", Artifact: "a", Version: "1.0+osera-patch.001"}}
	same := []status.FixedEntry{{CVE: "CVE-2024-0001", Coordinate: "org.example:a@1.0+osera-patch.001"}, {CVE: "CVE-2024-0002", Coordinate: "org.example:a@1.0+osera-patch.001"}}
	if needsBOM(pins, same) {
		t.Fatal("the same set should not need a BOM")
	}
	more := append(same, status.FixedEntry{CVE: "CVE-2024-0003", Coordinate: "org.example:b@2.0+osera-patch.001"})
	if !needsBOM(pins, more) {
		t.Fatal("a new coordinate should need a BOM")
	}
	if needsBOM(nil, nil) {
		t.Fatal("nothing fixed should not need a BOM")
	}
	if !needsBOM(nil, same) {
		t.Fatal("the first fix should need a BOM")
	}
}

// 5. The coordinate the line manager itself uploaded is known from the intent note.
func TestOwnUpload(t *testing.T) {
	c := releases.NewCoordinate("org.finos.osera", "osera-bom-dev-1.0.x", "2026.10.07")
	if ownUpload(nil, c) {
		t.Fatal("no note, not ours")
	}
	if !ownUpload(&intent.Intent{Kind: "bom", Ref: "org.finos.osera:osera-bom-dev-1.0.x@2026.10.07"}, c) {
		t.Fatal("the note names it, ours")
	}
	if ownUpload(&intent.Intent{Kind: "commit", Ref: "abc"}, c) {
		t.Fatal("a commit note is not an upload")
	}
}

// 6. The tag name is the date, then .2 when the date is taken.
func TestTagName(t *testing.T) {
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	if got := tagName(now, []string{"v2026.09.16"}); got != "v2026.10.07" {
		t.Fatalf("got %q", got)
	}
	if got := tagName(now, []string{"v2026.10.07"}); got != "v2026.10.07.2" {
		t.Fatalf("got %q", got)
	}
}

// origin is a repository standing in for GitHub, reached over the file transport.
type origin struct {
	dir  string
	repo *git.Repository
}

func newOrigin(t *testing.T) *origin {
	t.Helper()
	dir := t.TempDir()
	r, err := git.PlainInitWithOptions(dir, &git.PlainInitOptions{InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName("main")}})
	if err != nil {
		t.Fatal(err)
	}
	return &origin{dir: dir, repo: r}
}

func (o *origin) write(t *testing.T, path, content string) {
	t.Helper()
	full := filepath.Join(o.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (o *origin) commit(t *testing.T, message string) plumbing.Hash {
	t.Helper()
	w, err := o.repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		t.Fatal(err)
	}
	h, err := w.Commit(message, &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeGitHub answers the installation token and the board query, nothing else.
func fakeGitHub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"token": "ghs_test", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			w.Write([]byte(`{"data":{"organization":{"projectV2":{"items":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[
				{"content":{"__typename":"Issue","number":5,"title":"P0 CVE-2024-0002 in b 1.0","state":"OPEN","url":"u","repository":{"name":"patch-b"},"labels":{"nodes":[]}}},
				{"content":{"__typename":"Issue","number":6,"title":"P0 CVE-2024-0001 in a 1.0","state":"OPEN","url":"u","repository":{"name":"backlog"},"labels":{"nodes":[]}}}
			]}}}}}`))
		default:
			t.Errorf("unexpected GitHub call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// fakeNexus lists one patched coordinate with evidence naming CVE-2024-0001.
func fakeNexus(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/service/rest/v1/search":
			w.Write([]byte(`{"items":[{"group":"org.example","name":"a","version":"1.0+osera-patch.001","assets":[{"path":"/org/example/a/1.0+osera-patch.001/a-1.0+osera-patch.001.jar"}]}],"continuationToken":null}`))
		case strings.HasSuffix(r.URL.Path, "a-1.0+osera-patch.001-osera-evidence.yaml"):
			w.Write([]byte("schema: osera-patch-evidence/0.1.0\nproducer: controlplane-dev\nrelease: 1.0+osera-patch.001\nfixes:\n  - cve: CVE-2024-0001\n"))
		default:
			t.Errorf("unexpected Nexus call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func keyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "app.pem")
	raw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// 7. One whole pass in a dry run: the clone fetched, the graph present so no
// Maven, the scan fresh so no sources, the board and the release repository
// read, one entry fixed, one in progress, the line row and the status file
// written into the clone, the BOM and the commit only logged.
func TestOnceDry(t *testing.T) {
	// 1. the backlog repository with one line, its graph, two entries, the rules
	o := newOrigin(t)
	o.write(t, "supported-lines.csv", strings.Join(book.LineColumns, ",")+"\n"+testLine+",maven,org.example:bom@1.0,org.example:a@1.0,dev,a test,,,,,,,,,\n")
	writeGraph(t, o.dir, book.Line{ID: testLine, Anchor: "org.example:bom@1.0", Components: []string{"org.example:a@1.0"}}, book.Anchor{Group: "org.example", Artifact: "bom", Version: "1.0"})
	backlog := map[string]any{"schema_version": "0.6.0", "title": "test backlog", "standards_pack": "OSERA-SP-0.1.0", "generated": "2026-10-01T00:00:00Z", "entry_schema": "cve-backlog-entry-0.6.0.schema.json",
		"entries": []book.Entry{entry("CVE-2024-0001", "org.example:a", "1.0", book.EntryOpen), entry("CVE-2024-0002", "org.example:b", "1.0", book.EntryOpen)}}
	raw, _ := json.MarshalIndent(backlog, "", " ")
	o.write(t, "cve-backlog.json", string(raw))
	rulesFile, err := os.ReadFile("testdata/prioritisation.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o.write(t, "rules/prioritisation.yaml", string(rulesFile))
	o.repo.CreateTag("v2026.10.01", o.commit(t, "the test backlog"), nil)

	// 2. the fakes and the reconciler
	gh := fakeGitHub(t)
	defer gh.Close()
	nx := fakeNexus(t)
	defer nx.Close()
	cache := t.TempDir()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	os.WriteFile(filepath.Join(cache, "scan-"+testLine+".stamp"), []byte(now.Add(-time.Hour).Format(time.RFC3339)), 0o644)
	cfg := Config{
		Scanner: "sources",
		Owner:   "dev-finos-osera-forks", Repo: "backlog", CloneDir: filepath.Join(t.TempDir(), "clone"),
		App:         AppConfig{ID: 1, InstallationID: 2, KeyFile: keyFile(t)},
		BoardNumber: 1,
		Nexus:       NexusConfig{URL: nx.URL, User: "line-manager", Password: "pw", ReleaseRepository: "osera-releases-maven-01"},
		CacheDir:    cache, Interval: time.Minute, RescanInterval: 7 * 24 * time.Hour, Dry: true,
		RepoURL: o.dir, GitHubAPI: gh.URL, GraphQLURL: gh.URL + "/graphql",
		Now: func() time.Time { return now },
	}
	r, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 3. the pass
	records, err := r.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records %d", len(records))
	}
	rec := records[0]
	if rec.Status != status.InProgress || len(rec.Fixed) != 1 || len(rec.InProgress) != 1 || len(rec.Open) != 0 {
		t.Fatalf("record %+v", rec)
	}
	if rec.Fixed[0].CVE != "CVE-2024-0001" || rec.Fixed[0].Coordinate != "org.example:a@1.0+osera-patch.001" {
		t.Fatalf("fixed %+v", rec.Fixed)
	}
	if rec.InProgress[0].CVE != "CVE-2024-0002" || rec.BookVersion != "v2026.10.01" || rec.Consume != "" {
		t.Fatalf("record %+v", rec)
	}

	// 4. what was written into the clone, and what was not
	lines, err := book.ReadLines(filepath.Join(cfg.CloneDir, "supported-lines.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if lines[0].Status != status.InProgress || lines[0].Fixed != "1" || lines[0].InProgress != "1" || lines[0].Open != "0" || lines[0].BookVersion != "v2026.10.01" {
		t.Fatalf("line row %+v", lines[0])
	}
	if _, err := os.Stat(filepath.Join(cfg.CloneDir, "status", testLine+".json")); err != nil {
		t.Fatalf("status file: %v", err)
	}
	b, err := book.Read(filepath.Join(cfg.CloneDir, "cve-backlog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Entries[0].Status != book.EntryFixed || b.Entries[1].Status != book.EntryInProgress || b.Entries[1].Repository != "patch-b" {
		t.Fatalf("backlog %+v", b.Entries)
	}
	if _, err := os.Stat(filepath.Join(cfg.CloneDir, "bom", testLine, "pom.xml")); err != nil {
		t.Fatalf("the BOM should be staged in the clone even in a dry run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache, "intent.json")); err == nil {
		t.Fatal("a dry run writes no intent")
	}
	if _, err := os.Stat(filepath.Join(cache, "evidence.json")); err != nil {
		t.Fatal("the evidence read should be cached")
	}
}

// 9. A graph a failed pass left in the worktree is kept on the following pass, even
// when origin moved on in between: no resolve, the line is reported from that graph.
func TestGraphLeftInWorktreeIsKept(t *testing.T) {
	// 1. the backlog repository with one line and no graph
	o := newOrigin(t)
	o.write(t, "supported-lines.csv", strings.Join(book.LineColumns, ",")+"\n"+testLine+",maven,org.example:bom@1.0,org.example:a@1.0,dev,a test,,,,,,,,,\n")
	backlog := map[string]any{"schema_version": "0.6.0", "title": "test backlog", "standards_pack": "OSERA-SP-0.1.0", "generated": "2026-10-01T00:00:00Z", "entry_schema": "cve-backlog-entry-0.6.0.schema.json",
		"entries": []book.Entry{entry("CVE-2024-0001", "org.example:a", "1.0", book.EntryOpen)}}
	raw, _ := json.MarshalIndent(backlog, "", " ")
	o.write(t, "cve-backlog.json", string(raw))
	rulesFile, err := os.ReadFile("testdata/prioritisation.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o.write(t, "rules/prioritisation.yaml", string(rulesFile))
	o.repo.CreateTag("v2026.10.01", o.commit(t, "the test backlog"), nil)

	// 2. the reconciler, its clone made
	gh := fakeGitHub(t)
	defer gh.Close()
	nx := fakeNexus(t)
	defer nx.Close()
	cache := t.TempDir()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	os.WriteFile(filepath.Join(cache, "scan-"+testLine+".stamp"), []byte(now.Add(-time.Hour).Format(time.RFC3339)), 0o644)
	cfg := Config{
		Scanner: "sources",
		Owner:   "dev-finos-osera-forks", Repo: "backlog", CloneDir: filepath.Join(t.TempDir(), "clone"),
		App:         AppConfig{ID: 1, InstallationID: 2, KeyFile: keyFile(t)},
		BoardNumber: 1,
		Nexus:       NexusConfig{URL: nx.URL, User: "line-manager", Password: "pw", ReleaseRepository: "osera-releases-maven-01"},
		CacheDir:    cache, Interval: time.Minute, RescanInterval: 7 * 24 * time.Hour, Dry: true,
		RepoURL: o.dir, GitHubAPI: gh.URL, GraphQLURL: gh.URL + "/graphql",
		Now: func() time.Time { return now },
	}
	r, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 3. what a failed pass leaves: the graph in the worktree, not committed; then origin moves on
	writeGraph(t, cfg.CloneDir, book.Line{ID: testLine, Anchor: "org.example:bom@1.0", Components: []string{"org.example:a@1.0"}}, book.Anchor{Group: "org.example", Artifact: "bom", Version: "1.0"})
	o.write(t, "README.md", "moved on\n")
	o.commit(t, "someone else's commit")

	// 4. the following pass keeps the graph: no resolve (there is no anchor to fetch), one record
	records, err := r.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Line != testLine {
		t.Fatalf("records %+v", records)
	}
	if _, err := os.Stat(filepath.Join(cfg.CloneDir, filepath.FromSlash(graphPath(testLine)))); err != nil {
		t.Fatalf("the graph left in the worktree was lost: %v", err)
	}
}
