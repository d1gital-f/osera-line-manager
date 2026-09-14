// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// origin is a repository standing in for GitHub: a worktree the test commits
// in, reached by the clone over the local file transport.
type origin struct {
	dir  string
	repo *git.Repository
}

func newOrigin(t *testing.T) *origin {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInitWithOptions(dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName(Branch)},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := &origin{dir: dir, repo: repo}
	o.commit(t, "supported-lines.csv", "line_id\n", "the first commit")
	return o
}

func (o *origin) commit(t *testing.T, path, content, message string) plumbing.Hash {
	t.Helper()
	if err := os.WriteFile(filepath.Join(o.dir, path), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	worktree, err := o.repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add(path); err != nil {
		t.Fatal(err)
	}
	hash, err := worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func (o *origin) tag(t *testing.T, name string, hash plumbing.Hash) {
	t.Helper()
	if _, err := o.repo.CreateTag(name, hash, nil); err != nil {
		t.Fatal(err)
	}
}

// 1. A fresh clone, a second Open keeps it, a wrong origin replaces it.
func TestOpen(t *testing.T) {
	o := newOrigin(t)
	dir := filepath.Join(t.TempDir(), "clone")
	c, err := Open(context.Background(), dir, o.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	commit, tree, err := c.Head()
	if err != nil {
		t.Fatal(err)
	}
	if commit == "" || tree == "" {
		t.Fatalf("head %q tree %q", commit, tree)
	}
	raw, err := c.File("supported-lines.csv")
	if err != nil || string(raw) != "line_id\n" {
		t.Fatalf("file %q %v", raw, err)
	}

	// the same origin: kept
	again, err := Open(context.Background(), dir, o.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Dir != dir {
		t.Fatalf("dir %q", again.Dir)
	}

	// another origin: replaced
	other := newOrigin(t)
	replaced, err := Open(context.Background(), dir, other.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.URL != other.dir {
		t.Fatalf("url %q", replaced.URL)
	}
}

// 2. A new commit at origin is fast forwarded, no reset reported.
func TestFetchFastForward(t *testing.T) {
	o := newOrigin(t)
	c, err := Open(context.Background(), filepath.Join(t.TempDir(), "clone"), o.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := o.commit(t, "supported-lines.csv", "line_id\nspring-boot-2.7.x\n", "a line")
	res, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Reset {
		t.Fatal("a fast forward reported as a reset")
	}
	if res.After != next {
		t.Fatalf("after %s, want %s", res.After, next)
	}
	raw, _ := c.File("supported-lines.csv")
	if string(raw) != "line_id\nspring-boot-2.7.x\n" {
		t.Fatalf("worktree not moved: %q", raw)
	}

	// nothing new: nothing moves
	res, err = c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Before != res.After || res.Reset {
		t.Fatalf("unexpected move %+v", res)
	}
}

// 3. A local commit that origin does not have is thrown away: reset reported.
func TestFetchReset(t *testing.T) {
	o := newOrigin(t)
	c, err := Open(context.Background(), filepath.Join(t.TempDir(), "clone"), o.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := &origin{dir: c.Dir, repo: c.repo}
	local.commit(t, "stray.txt", "not derived from anything\n", "a stray local commit")
	next := o.commit(t, "supported-lines.csv", "line_id\ndev-1.0.x\n", "origin moved")
	res, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reset {
		t.Fatal("a diverged clone was not reported as reset")
	}
	if res.After != next {
		t.Fatalf("after %s, want %s", res.After, next)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "stray.txt")); !os.IsNotExist(err) {
		t.Fatal("the stray file survived the reset")
	}
}

// 4. Tags: only v*, the highest by version order, annotated or not.
func TestTags(t *testing.T) {
	o := newOrigin(t)
	first := o.commit(t, "a.txt", "a", "a")
	o.tag(t, "v2026.09.09", first)
	second := o.commit(t, "b.txt", "b", "b")
	o.tag(t, "v2026.09.16", second)
	o.tag(t, "not-a-version", second)
	c, err := Open(context.Background(), filepath.Join(t.TempDir(), "clone"), o.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := c.Tags()
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 {
		t.Fatalf("tags %v", tags)
	}
	name, sha, err := c.LatestTag()
	if err != nil {
		t.Fatal(err)
	}
	if name != "v2026.09.16" || sha != second.String() {
		t.Fatalf("latest %s at %s", name, sha)
	}
}

// 5. The version order the tags use.
func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"v2026.09.09", "v2026.09.10", true},
		{"v2026.09.10", "v2026.09.09", false},
		{"v1", "v2", true},
		{"v2026.09.09", "v2026.09.09.2", true},
		{"v2026.10.01", "v2026.09.30", false},
	}
	for _, tc := range cases {
		if versionLess(tc.a, tc.b) != tc.less {
			t.Errorf("versionLess(%s, %s) = %v", tc.a, tc.b, !tc.less)
		}
	}
}
