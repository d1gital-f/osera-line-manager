// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package repo is how the line manager works with the backlog repository. Reads
// come from a local clone kept on a volume, fetched and fast forwarded on every
// pass, never merged, never rebased. Writes never leave the clone as a push: a
// commit is made through GitHub's git database API as the App, so GitHub signs
// it and the repository's signature rule holds. The clone is then fetched again.
package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// Branch is the one branch the line manager follows.
const Branch = "main"

// Clone is the local copy of the backlog repository.
type Clone struct {
	Dir  string
	URL  string
	Auth transport.AuthMethod
	repo *git.Repository
}

// FetchResult says what a fetch did to the local branch.
type FetchResult struct {
	// Before and After are the local head before and after the fetch.
	Before plumbing.Hash
	After  plumbing.Hash
	// Reset is true when local main was not an ancestor of origin and was reset to it.
	Reset bool
}

// Open opens the clone at dir when it exists and points at url, otherwise
// removes whatever is there and clones fresh, main only.
func Open(ctx context.Context, dir, url string, auth transport.AuthMethod) (*Clone, error) {
	c := &Clone{Dir: dir, URL: url, Auth: auth}

	// 1. an existing clone with the right origin is kept
	existing, err := git.PlainOpen(dir)
	if err == nil {
		remote, remoteErr := existing.Remote(git.DefaultRemoteName)
		if remoteErr == nil && len(remote.Config().URLs) > 0 && remote.Config().URLs[0] == url {
			c.repo = existing
			return c, nil
		}
	}

	// 2. anything else goes, and a fresh clone takes its place
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("removing %s: %w", dir, err)
	}
	fresh, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:           url,
		Auth:          auth,
		ReferenceName: plumbing.NewBranchReferenceName(Branch),
		SingleBranch:  true,
		Tags:          git.AllTags,
	})
	if err != nil {
		return nil, fmt.Errorf("cloning %s: %w", url, err)
	}
	c.repo = fresh
	return c, nil
}

// Fetch fetches origin and moves local main to origin's main: a fast forward
// when local main is an ancestor, a hard reset otherwise. The worktree ends at
// origin's main either way, nothing local survives, by design.
func (c *Clone) Fetch(ctx context.Context) (FetchResult, error) {
	var res FetchResult

	// 1. where we are
	head, err := c.repo.Head()
	if err != nil {
		return res, fmt.Errorf("reading head: %w", err)
	}
	res.Before = head.Hash()

	// 2. the fetch itself, main and the tags
	err = c.repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: git.DefaultRemoteName,
		Auth:       c.Auth,
		RefSpecs: []config.RefSpec{
			config.RefSpec("+refs/heads/" + Branch + ":refs/remotes/origin/" + Branch),
			config.RefSpec("+refs/tags/*:refs/tags/*"),
		},
		Tags:  git.AllTags,
		Force: true,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return res, fmt.Errorf("fetching %s: %w", c.URL, err)
	}

	// 3. where origin is
	remoteRef, err := c.repo.Reference(plumbing.NewRemoteReferenceName(git.DefaultRemoteName, Branch), true)
	if err != nil {
		return res, fmt.Errorf("reading origin/%s: %w", Branch, err)
	}
	res.After = remoteRef.Hash()
	if res.After == res.Before {
		return res, nil
	}

	// 4. fast forward or reset: the same move, a different word
	local, err := c.repo.CommitObject(res.Before)
	if err != nil {
		return res, fmt.Errorf("reading the local commit: %w", err)
	}
	remote, err := c.repo.CommitObject(res.After)
	if err != nil {
		return res, fmt.Errorf("reading origin's commit: %w", err)
	}
	ancestor, err := local.IsAncestor(remote)
	if err != nil {
		return res, fmt.Errorf("comparing the two commits: %w", err)
	}
	if !ancestor {
		res.Reset = true
	}
	worktree, err := c.repo.Worktree()
	if err != nil {
		return res, err
	}

	// 5. on a fast forward, a graph built in a pass that failed before its commit stays:
	//    the worktree files under graphs/ are kept across the move; a reset drops them
	var kept map[string][]byte
	if !res.Reset {
		kept = c.readTree(GraphsDir)
	}
	err = worktree.Reset(&git.ResetOptions{Commit: res.After, Mode: git.HardReset})
	if err != nil {
		return res, fmt.Errorf("moving %s to origin: %w", Branch, err)
	}
	for rel, content := range kept {
		path := filepath.Join(c.Dir, filepath.FromSlash(rel))
		now, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(now, content) {
			continue
		}
		err = os.MkdirAll(filepath.Dir(path), 0o755)
		if err != nil {
			return res, err
		}
		err = os.WriteFile(path, content, 0o644)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// GraphsDir is the folder of the graphs in the repository, the one folder a fetch keeps.
const GraphsDir = "graphs"

// readTree reads every file under a folder of the worktree, keyed by its slash path.
func (c *Clone) readTree(dir string) map[string][]byte {
	out := map[string][]byte{}
	root := filepath.Join(c.Dir, dir)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(c.Dir, path)
		if relErr != nil {
			return nil
		}
		out[filepath.ToSlash(rel)] = content
		return nil
	})
	return out
}

// Head returns the commit id and the tree id the clone is at.
func (c *Clone) Head() (commit, tree string, err error) {
	ref, err := c.repo.Head()
	if err != nil {
		return "", "", err
	}
	obj, err := c.repo.CommitObject(ref.Hash())
	if err != nil {
		return "", "", err
	}
	return ref.Hash().String(), obj.TreeHash.String(), nil
}

// File reads one file of the clone at head.
func (c *Clone) File(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(c.Dir, filepath.FromSlash(path)))
}

// Tags lists the v* tags of the clone, in no particular order.
func (c *Clone) Tags() ([]string, error) {
	iter, err := c.repo.Tags()
	if err != nil {
		return nil, err
	}
	var names []string
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		name := ref.Name().Short()
		if strings.HasPrefix(name, "v") {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// LatestTag returns the highest v* tag by version order, and its commit.
func (c *Clone) LatestTag() (string, string, error) {
	// 1. the candidates
	names, err := c.Tags()
	if err != nil {
		return "", "", err
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("no v* tag in %s", c.URL)
	}

	// 2. the highest
	sort.Slice(names, func(i, j int) bool {
		return versionLess(names[j], names[i])
	})
	ref, err := c.repo.Tag(names[0])
	if err != nil {
		return "", "", err
	}
	hash := ref.Hash()
	tagObject, err := c.repo.TagObject(hash)
	if err == nil {
		hash = tagObject.Target
	}
	return names[0], hash.String(), nil
}

// versionLess orders v2026.09.09 before v2026.09.10 and v1 before v2, numerically per segment.
func versionLess(a, b string) bool {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, _ := strconv.Atoi(as[i])
		bi, _ := strconv.Atoi(bs[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}
