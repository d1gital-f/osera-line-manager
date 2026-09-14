// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fixedToken string

func (f fixedToken) Token(context.Context) (string, error) {
	return string(f), nil
}

// request is what the fake GitHub saw.
type request struct {
	Method string
	Path   string
	Body   map[string]any
}

// fakeGitHub answers a scripted set of routes and records every request.
func fakeGitHub(t *testing.T, routes map[string]func(w http.ResponseWriter, body map[string]any)) (*httptest.Server, *[]request) {
	t.Helper()
	var seen []request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_test" {
			t.Errorf("authorization %q on %s %s", r.Header.Get("Authorization"), r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &body)
		}
		seen = append(seen, request{Method: r.Method, Path: r.URL.RequestURI(), Body: body})
		handler, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		handler(w, body)
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func answer(status int, body string) func(w http.ResponseWriter, _ map[string]any) {
	return func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func newTestClient(server *httptest.Server) *Client {
	c := NewClient(fixedToken("ghs_test"))
	c.BaseURL = server.URL
	c.HTTP = server.Client()
	return c
}

// 1. A commit on a branch that does not exist yet: blobs, tree, commit, then the ref is created.
func TestCommitNewBranch(t *testing.T) {
	server, seen := fakeGitHub(t, map[string]func(http.ResponseWriter, map[string]any){
		"POST /repos/o/r/git/blobs":       answer(201, `{"sha":"blob1"}`),
		"POST /repos/o/r/git/trees":       answer(201, `{"sha":"tree1"}`),
		"POST /repos/o/r/git/commits":     answer(201, `{"sha":"commit1"}`),
		"GET /repos/o/r/git/ref/heads/lm": answer(404, `{"message":"Not Found"}`),
		"POST /repos/o/r/git/refs":        answer(201, `{"ref":"refs/heads/lm"}`),
	})
	c := newTestClient(server)
	ref, err := c.Commit(context.Background(), "o", "r", "lm", CommitRef{SHA: "parent1", Tree: "ptree"}, map[string][]byte{
		"supported-lines.csv": []byte("line_id\n"),
		"old.json":            nil,
	}, "the row")
	if err != nil {
		t.Fatal(err)
	}
	if ref.SHA != "commit1" || ref.Tree != "tree1" {
		t.Fatalf("ref %+v", ref)
	}

	// the tree: one entry with a sha, one with null
	var tree request
	for _, r := range *seen {
		if r.Method == http.MethodPost && r.Path == "/repos/o/r/git/trees" {
			tree = r
		}
	}
	if tree.Body["base_tree"] != "ptree" {
		t.Fatalf("base tree %v", tree.Body["base_tree"])
	}
	entries := tree.Body["tree"].([]any)
	if len(entries) != 2 {
		t.Fatalf("%d entries", len(entries))
	}
	for _, e := range entries {
		entry := e.(map[string]any)
		sha, present := entry["sha"]
		if !present {
			t.Fatalf("sha missing on %v", entry)
		}
		if entry["path"] == "old.json" && sha != nil {
			t.Fatalf("delete entry carries a sha: %v", entry)
		}
		if entry["path"] == "supported-lines.csv" && sha != "blob1" {
			t.Fatalf("kept entry sha %v", sha)
		}
	}

	// the commit: no author, the parent named
	var commit request
	for _, r := range *seen {
		if r.Method == http.MethodPost && r.Path == "/repos/o/r/git/commits" {
			commit = r
		}
	}
	if _, has := commit.Body["author"]; has {
		t.Fatal("an author was set, the commit must be the App's")
	}
	parents := commit.Body["parents"].([]any)
	if len(parents) != 1 || parents[0] != "parent1" {
		t.Fatalf("parents %v", parents)
	}

	// the ref: created, not moved
	last := (*seen)[len(*seen)-1]
	if last.Method != http.MethodPost || last.Path != "/repos/o/r/git/refs" || last.Body["ref"] != "refs/heads/lm" || last.Body["sha"] != "commit1" {
		t.Fatalf("last call %+v", last)
	}
}

// 2. A commit on a branch that exists: the ref is moved, never forced.
func TestCommitExistingBranch(t *testing.T) {
	server, seen := fakeGitHub(t, map[string]func(http.ResponseWriter, map[string]any){
		"POST /repos/o/r/git/blobs":            answer(201, `{"sha":"blob1"}`),
		"POST /repos/o/r/git/trees":            answer(201, `{"sha":"tree2"}`),
		"POST /repos/o/r/git/commits":          answer(201, `{"sha":"commit2"}`),
		"GET /repos/o/r/git/ref/heads/main":    answer(200, `{"ref":"refs/heads/main"}`),
		"PATCH /repos/o/r/git/refs/heads/main": answer(200, `{"ref":"refs/heads/main"}`),
	})
	c := newTestClient(server)
	_, err := c.Commit(context.Background(), "o", "r", "main", CommitRef{SHA: "p", Tree: "t"}, map[string][]byte{"a": []byte("a")}, "m")
	if err != nil {
		t.Fatal(err)
	}
	last := (*seen)[len(*seen)-1]
	if last.Method != http.MethodPatch || last.Path != "/repos/o/r/git/refs/heads/main" || last.Body["sha"] != "commit2" || last.Body["force"] != false {
		t.Fatalf("last call %+v", last)
	}
}

// 3. A pull request already open from the head is refreshed, not doubled; none open: created.
func TestOpenPullRequest(t *testing.T) {
	server, seen := fakeGitHub(t, map[string]func(http.ResponseWriter, map[string]any){
		"GET /repos/o/r/pulls":     answer(200, `[{"number":7}]`),
		"PATCH /repos/o/r/pulls/7": answer(200, `{"number":7}`),
	})
	c := newTestClient(server)
	number, err := c.OpenPullRequest(context.Background(), "o", "r", "line-manager/x", "main", "t", "b")
	if err != nil || number != 7 {
		t.Fatalf("number %d %v", number, err)
	}
	first := (*seen)[0]
	if first.Path != "/repos/o/r/pulls?base=main&head=o%3Aline-manager%2Fx&state=open" {
		t.Fatalf("search %s", first.Path)
	}
	if (*seen)[1].Method != http.MethodPatch {
		t.Fatalf("second call %+v", (*seen)[1])
	}

	server2, seen2 := fakeGitHub(t, map[string]func(http.ResponseWriter, map[string]any){
		"GET /repos/o/r/pulls":  answer(200, `[]`),
		"POST /repos/o/r/pulls": answer(201, `{"number":8}`),
	})
	c2 := newTestClient(server2)
	number, err = c2.OpenPullRequest(context.Background(), "o", "r", "line-manager/x", "main", "t", "b")
	if err != nil || number != 8 {
		t.Fatalf("number %d %v", number, err)
	}
	created := (*seen2)[1]
	if created.Body["head"] != "line-manager/x" || created.Body["base"] != "main" {
		t.Fatalf("created %+v", created.Body)
	}
}

// 4. Merge, tag, verified, checks, close and reopen: the right call each.
func TestSmallCalls(t *testing.T) {
	server, seen := fakeGitHub(t, map[string]func(http.ResponseWriter, map[string]any){
		"PUT /repos/o/r/pulls/7/merge":          answer(200, `{"merged":true}`),
		"POST /repos/o/r/git/refs":              answer(201, `{}`),
		"GET /repos/o/r/commits/abc":            answer(200, `{"commit":{"verification":{"verified":true}}}`),
		"GET /repos/o/r/commits/abc/check-runs": answer(200, `{"check_runs":[{"name":"validate","conclusion":"success"}]}`),
		"POST /repos/o/r/issues/12/comments":    answer(201, `{}`),
		"PATCH /repos/o/r/issues/12":            answer(200, `{}`),
	})
	c := newTestClient(server)
	ctx := context.Background()
	if err := c.MergePullRequest(ctx, "o", "r", 7); err != nil {
		t.Fatal(err)
	}
	if err := c.Tag(ctx, "o", "r", "v2026.09.16", "abc"); err != nil {
		t.Fatal(err)
	}
	verified, err := c.Verified(ctx, "o", "r", "abc")
	if err != nil || !verified {
		t.Fatalf("verified %v %v", verified, err)
	}
	checks, err := c.Checks(ctx, "o", "r", "abc")
	if err != nil || len(checks) != 1 || checks[0].Name != "validate" || checks[0].Conclusion != "success" {
		t.Fatalf("checks %+v %v", checks, err)
	}
	if err := c.CloseIssue(ctx, "o", "r", 12, "fixed by x"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReopenIssue(ctx, "o", "r", 12, "back"); err != nil {
		t.Fatal(err)
	}
	tagCall := (*seen)[1]
	if tagCall.Body["ref"] != "refs/tags/v2026.09.16" || tagCall.Body["sha"] != "abc" {
		t.Fatalf("tag %+v", tagCall.Body)
	}
	closeState := (*seen)[5]
	if closeState.Method != http.MethodPatch || closeState.Body["state"] != "closed" {
		t.Fatalf("close %+v", closeState)
	}
	reopenState := (*seen)[7]
	if reopenState.Body["state"] != "open" {
		t.Fatalf("reopen %+v", reopenState)
	}
	if (*seen)[4].Body["body"] != "fixed by x" {
		t.Fatalf("comment %+v", (*seen)[4].Body)
	}
}

// 5. A non 2xx answer is an error carrying the status.
func TestAPIError(t *testing.T) {
	server, _ := fakeGitHub(t, map[string]func(http.ResponseWriter, map[string]any){
		"PUT /repos/o/r/pulls/7/merge": answer(405, `{"message":"not mergeable"}`),
	})
	c := newTestClient(server)
	err := c.MergePullRequest(context.Background(), "o", "r", 7)
	if err == nil {
		t.Fatal("a 405 went unnoticed")
	}
}
