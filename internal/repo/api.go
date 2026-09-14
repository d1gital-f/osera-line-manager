// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client writes to GitHub as the App: commits through the git database API,
// pull requests, tags, issue comments. Every call carries the installation token.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Tokens  TokenSource
}

// NewClient returns a client against GitHub's API with the given token source.
func NewClient(tokens TokenSource) *Client {
	return &Client{
		BaseURL: DefaultAPI,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		Tokens:  tokens,
	}
}

// CommitRef names a commit and its tree.
type CommitRef struct {
	SHA  string
	Tree string
}

// Check is one check run on a commit.
type Check struct {
	Name       string
	Conclusion string
}

// Commit writes one commit on a branch: one blob per file, one tree on the
// parent's tree, one commit with the parent, then the branch ref, created when
// absent and moved otherwise. A nil content deletes the path. No author is set,
// so GitHub attributes the commit to the App and signs it.
func (c *Client) Commit(ctx context.Context, owner, repo, branch string, parent CommitRef, files map[string][]byte, message string) (CommitRef, error) {
	base := fmt.Sprintf("/repos/%s/%s", owner, repo)

	// 1. one blob per file kept, a null sha per file deleted
	type entry struct {
		Path string  `json:"path"`
		Mode string  `json:"mode"`
		Type string  `json:"type"`
		SHA  *string `json:"sha"`
	}
	var entries []entry
	for path, content := range files {
		if content == nil {
			entries = append(entries, entry{Path: path, Mode: "100644", Type: "blob", SHA: nil})
			continue
		}
		var blob struct {
			SHA string `json:"sha"`
		}
		err := c.call(ctx, http.MethodPost, base+"/git/blobs", map[string]string{
			"content":  base64.StdEncoding.EncodeToString(content),
			"encoding": "base64",
		}, &blob)
		if err != nil {
			return CommitRef{}, fmt.Errorf("uploading %s: %w", path, err)
		}
		sha := blob.SHA
		entries = append(entries, entry{Path: path, Mode: "100644", Type: "blob", SHA: &sha})
	}

	// 2. one tree on the parent's
	var tree struct {
		SHA string `json:"sha"`
	}
	err := c.call(ctx, http.MethodPost, base+"/git/trees", map[string]any{
		"base_tree": parent.Tree,
		"tree":      entries,
	}, &tree)
	if err != nil {
		return CommitRef{}, fmt.Errorf("writing the tree: %w", err)
	}

	// 3. one commit, no author, so it is the App's and GitHub signs it
	var commit struct {
		SHA string `json:"sha"`
	}
	err = c.call(ctx, http.MethodPost, base+"/git/commits", map[string]any{
		"message": message,
		"tree":    tree.SHA,
		"parents": []string{parent.SHA},
	}, &commit)
	if err != nil {
		return CommitRef{}, fmt.Errorf("writing the commit: %w", err)
	}

	// 4. the branch: moved when it exists, created when it does not
	var existing struct {
		Ref string `json:"ref"`
	}
	err = c.call(ctx, http.MethodGet, base+"/git/ref/heads/"+branch, nil, &existing)
	if err == nil {
		err = c.call(ctx, http.MethodPatch, base+"/git/refs/heads/"+branch, map[string]any{
			"sha": commit.SHA,
			// the line manager's own branch: a refreshed pass sits on today's main, not on
			// the branch's old tip, so the move is never a fast forward; main is never forced
			"force": ownBranch(branch),
		}, nil)
		if err != nil {
			return CommitRef{}, fmt.Errorf("moving %s: %w", branch, err)
		}
		return CommitRef{SHA: commit.SHA, Tree: tree.SHA}, nil
	}
	if !isNotFound(err) {
		return CommitRef{}, fmt.Errorf("reading %s: %w", branch, err)
	}
	err = c.call(ctx, http.MethodPost, base+"/git/refs", map[string]string{
		"ref": "refs/heads/" + branch,
		"sha": commit.SHA,
	}, nil)
	if err != nil {
		return CommitRef{}, fmt.Errorf("creating %s: %w", branch, err)
	}
	return CommitRef{SHA: commit.SHA, Tree: tree.SHA}, nil
}

// OpenPullRequest opens a pull request from head into base, or refreshes the
// body of the one already open from that head. Returns its number.
func (c *Client) OpenPullRequest(ctx context.Context, owner, repo, head, base, title, body string) (int, error) {
	prefix := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)

	// 1. one already open from this head is refreshed, never doubled
	query := url.Values{}
	query.Set("head", owner+":"+head)
	query.Set("base", base)
	query.Set("state", "open")
	var open []struct {
		Number int `json:"number"`
	}
	err := c.call(ctx, http.MethodGet, prefix+"?"+query.Encode(), nil, &open)
	if err != nil {
		return 0, fmt.Errorf("looking for an open pull request from %s: %w", head, err)
	}
	if len(open) > 0 {
		number := open[0].Number
		err = c.call(ctx, http.MethodPatch, fmt.Sprintf("%s/%d", prefix, number), map[string]string{
			"title": title,
			"body":  body,
		}, nil)
		if err != nil {
			return 0, fmt.Errorf("refreshing pull request %d: %w", number, err)
		}
		return number, nil
	}

	// 2. a new one
	var created struct {
		Number int `json:"number"`
	}
	err = c.call(ctx, http.MethodPost, prefix, map[string]string{
		"title": title,
		"head":  head,
		"base":  base,
		"body":  body,
	}, &created)
	if err != nil {
		return 0, fmt.Errorf("opening the pull request from %s: %w", head, err)
	}
	return created.Number, nil
}

// MergePullRequest merges one pull request with a merge commit.
func (c *Client) MergePullRequest(ctx context.Context, owner, repo string, number int) error {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/merge", owner, repo, number)
	var answer struct {
		Merged bool `json:"merged"`
	}
	err := c.call(ctx, http.MethodPut, path, map[string]string{"merge_method": "merge"}, &answer)
	if err != nil {
		return fmt.Errorf("merging pull request %d: %w", number, err)
	}
	if !answer.Merged {
		return fmt.Errorf("pull request %d was not merged", number)
	}
	return nil
}

// Tag creates a lightweight tag at a commit.
func (c *Client) Tag(ctx context.Context, owner, repo, name, sha string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo)
	err := c.call(ctx, http.MethodPost, path, map[string]string{
		"ref": "refs/tags/" + name,
		"sha": sha,
	}, nil)
	if err != nil {
		return fmt.Errorf("tagging %s: %w", name, err)
	}
	return nil
}

// Verified says whether GitHub shows the commit's signature as verified: the
// proof that a commit made through the API as the App is signed by GitHub.
func (c *Client) Verified(ctx context.Context, owner, repo, sha string) (bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, sha)
	var answer struct {
		Commit struct {
			Verification struct {
				Verified bool `json:"verified"`
			} `json:"verification"`
		} `json:"commit"`
	}
	err := c.call(ctx, http.MethodGet, path, nil, &answer)
	if err != nil {
		return false, fmt.Errorf("reading commit %s: %w", sha, err)
	}
	return answer.Commit.Verification.Verified, nil
}

// Checks lists the check runs on a commit with their conclusion.
func (c *Client) Checks(ctx context.Context, owner, repo, sha string) ([]Check, error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs", owner, repo, sha)
	var answer struct {
		CheckRuns []struct {
			Name       string `json:"name"`
			Conclusion string `json:"conclusion"`
		} `json:"check_runs"`
	}
	err := c.call(ctx, http.MethodGet, path, nil, &answer)
	if err != nil {
		return nil, fmt.Errorf("reading the checks of %s: %w", sha, err)
	}
	var checks []Check
	for _, run := range answer.CheckRuns {
		checks = append(checks, Check{Name: run.Name, Conclusion: run.Conclusion})
	}
	return checks, nil
}

// Comment writes one comment on an issue or a pull request.
func (c *Client) Comment(ctx context.Context, owner, repo string, number int, body string) error {
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, number)
	err := c.call(ctx, http.MethodPost, path, map[string]string{"body": body}, nil)
	if err != nil {
		return fmt.Errorf("commenting on #%d: %w", number, err)
	}
	return nil
}

// CloseIssue comments on an issue, then closes it.
func (c *Client) CloseIssue(ctx context.Context, owner, repo string, number int, comment string) error {
	return c.setIssueState(ctx, owner, repo, number, comment, "closed")
}

// ReopenIssue comments on an issue, then reopens it.
func (c *Client) ReopenIssue(ctx context.Context, owner, repo string, number int, comment string) error {
	return c.setIssueState(ctx, owner, repo, number, comment, "open")
}

func (c *Client) setIssueState(ctx context.Context, owner, repo string, number int, comment, state string) error {
	prefix := fmt.Sprintf("/repos/%s/%s/issues/%d", owner, repo, number)

	// 1. the comment, so the reason is on the issue before its state moves
	err := c.call(ctx, http.MethodPost, prefix+"/comments", map[string]string{"body": comment}, nil)
	if err != nil {
		return fmt.Errorf("commenting on issue %d: %w", number, err)
	}

	// 2. the state
	err = c.call(ctx, http.MethodPatch, prefix, map[string]string{"state": state}, nil)
	if err != nil {
		return fmt.Errorf("setting issue %d to %s: %w", number, state, err)
	}
	return nil
}

// apiError is a non 2xx answer from GitHub.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

func isNotFound(err error) bool {
	apiErr, ok := err.(*apiError)
	if !ok {
		return false
	}
	return apiErr.Status == http.StatusNotFound
}

// call performs one request with the installation token and decodes a JSON answer when asked.
func (c *Client) call(ctx context.Context, method, path string, body any, out any) error {
	// 1. the token
	token, err := c.Tokens.Token(ctx)
	if err != nil {
		return err
	}

	// 2. the request
	var payload io.Reader
	if body != nil {
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return marshalErr
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	// 3. the answer
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{Status: resp.StatusCode, Body: string(answer)}
	}
	if out == nil || len(answer) == 0 {
		return nil
	}
	return json.Unmarshal(answer, out)
}

// ownBranch says whether a branch is the line manager's own scratch branch, which it may move freely.
func ownBranch(branch string) bool {
	return strings.HasPrefix(branch, "line-manager/")
}
