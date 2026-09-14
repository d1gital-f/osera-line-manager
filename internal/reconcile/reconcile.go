// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package reconcile is the loop. One pass reads the backlog repository, the
// board and the release repository, computes one record per line, and writes
// what changed: the graph, the backlog, the BOM, the line row, the status file,
// as one pull request the line manager merges itself. Every pass starts from
// the inputs and is safe to repeat. Nothing here decides a CVE is fixed: the
// release repository says so, the line manager reports it.
package reconcile

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/d1gital-f/osera-line-manager/internal/board"
	"github.com/d1gital-f/osera-line-manager/internal/graph"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
	"github.com/d1gital-f/osera-line-manager/internal/repo"
	"github.com/d1gital-f/osera-line-manager/internal/scan"
)

// AppConfig identifies the GitHub App the line manager acts as.
type AppConfig struct {
	ID             int64
	InstallationID int64
	// KeyFile is the path of the App's private key, PEM.
	KeyFile string
}

// NexusConfig is the release repository and the account that reads it and
// publishes the BOMs.
type NexusConfig struct {
	URL               string
	User              string
	Password          string
	ReleaseRepository string
}

// Config is what one line manager instance watches and how.
type Config struct {
	// Owner and Repo name the backlog repository, owner/repo.
	Owner string
	Repo  string
	// CloneDir is where the clone lives, on a volume.
	CloneDir string
	App      AppConfig
	// BoardNumber is the organisation project number of the board.
	BoardNumber int
	Nexus       NexusConfig
	// WebhookSecret is what Nexus signs its deliveries with.
	WebhookSecret string
	// MavenRepositories are the repositories the resolver reads, in order, Central alone when
	// empty; a repository under the Nexus address is read with the Nexus account.
	MavenRepositories []string
	// MavenWorkers is how many Maven probes run at once, four when zero.
	MavenWorkers int
	// CacheDir holds the scan caches, the evidence cache, the scan stamps and the intent file.
	CacheDir string
	// Interval is the time between passes; RescanInterval between two scans of one line's graph.
	Interval       time.Duration
	RescanInterval time.Duration
	// DevAdvisories is the path, inside the repository, of the dev only advisory file. Empty in production.
	DevAdvisories string
	// Scanner picks how CVEs are found: "grype" (the default, grype over the graph file) or
	// "sources" (OSV, CISA KEV, FIRST EPSS and NVD called one by one, kept for comparison).
	Scanner string
	// GrypeBinary is the grype executable, grype on PATH when empty.
	GrypeBinary string
	// Dry computes and logs, writes nothing to GitHub or Nexus.
	Dry bool
	// Listen is the address of the health, status and webhook server.
	Listen string

	// LocalDir, when set, is a directory with the backlog files read in place of
	// the clone: no GitHub, no Nexus, no board. The status command uses it.
	LocalDir string
	// LocalVersion is the book version recorded on a local run.
	LocalVersion string

	// The addresses below are for tests; empty means the real thing.
	RepoURL    string
	GitHubAPI  string
	GraphQLURL string
	// Now is the clock, replaceable in tests.
	Now func() time.Time
	// CheckTimeout bounds the wait for the checks on a pull request; ten minutes when zero.
	CheckTimeout time.Duration
}

// Reconciler holds the clients one instance uses across passes.
type Reconciler struct {
	cfg      Config
	clone    *repo.Clone
	app      *repo.App
	api      *repo.Client
	board    *board.Client
	nexus    *releases.Client
	scanner  *scan.Scanner
	grype    *scan.GrypeScanner
	resolver *graph.Resolver
	now      func() time.Time
	// wake receives one signal per accepted webhook event; the loop coalesces them.
	wake chan struct{}
}

// New builds the clients from the configuration. Nothing is read yet.
func New(ctx context.Context, cfg Config) (*Reconciler, error) {
	r := &Reconciler{cfg: cfg, now: cfg.Now, wake: make(chan struct{}, 1)}
	if r.now == nil {
		r.now = time.Now
	}
	if cfg.CacheDir != "" {
		err := os.MkdirAll(cfg.CacheDir, 0o755)
		if err != nil {
			return nil, err
		}
	}

	// 1. the scanner and the resolver, the same in every mode
	r.scanner = scan.New(filepath.Join(cfg.CacheDir, "scan"))
	if cfg.Scanner != "sources" {
		r.grype = scan.NewGrype(cfg.GrypeBinary, filepath.Join(cfg.CacheDir, "grype"))
	}
	r.resolver = graph.NewResolver()
	r.resolver.Workers = cfg.MavenWorkers
	r.resolver.Progress = func(done, nodes, depth int) {
		if done == 0 {
			logf("resolve: %d roots, %d probes at a time", nodes, r.resolver.Workers)
			return
		}
		logf("resolve: %d probes done, %d nodes known, depth %d", done, nodes, depth)
	}
	if len(cfg.MavenRepositories) > 0 {
		r.resolver.RepositoryURLs = cfg.MavenRepositories
		for _, u := range cfg.MavenRepositories {
			if cfg.Nexus.URL != "" && strings.HasPrefix(u, strings.TrimSuffix(cfg.Nexus.URL, "/")) {
				r.resolver.Servers = append(r.resolver.Servers, graph.Server{URL: u, User: cfg.Nexus.User, Password: cfg.Nexus.Password})
			}
		}
	}

	// 2. local mode reads a directory and stops there
	if cfg.LocalDir != "" {
		return r, nil
	}

	// 3. the App and the API client
	key, err := os.ReadFile(cfg.App.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading the App key: %w", err)
	}
	r.app, err = repo.NewApp(cfg.App.ID, cfg.App.InstallationID, key, &http.Client{Timeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	if cfg.GitHubAPI != "" {
		r.app.BaseURL = cfg.GitHubAPI
	}
	r.api = repo.NewClient(r.app)
	if cfg.GitHubAPI != "" {
		r.api.BaseURL = cfg.GitHubAPI
	}

	// 4. the clone, fetched over HTTPS with the App's token
	url := cfg.RepoURL
	if url == "" {
		url = fmt.Sprintf("https://github.com/%s/%s.git", cfg.Owner, cfg.Repo)
	}
	r.clone, err = repo.Open(ctx, cfg.CloneDir, url, nil)
	if err != nil {
		return nil, err
	}

	// 5. the board and the release repository
	r.board = board.New(cfg.Owner, cfg.BoardNumber, "")
	if cfg.GraphQLURL != "" {
		r.board.URL = cfg.GraphQLURL
	}
	r.nexus = releases.New(cfg.Nexus.URL, cfg.Nexus.User, cfg.Nexus.Password)
	return r, nil
}

// auth gives the clone and the board the App's current token. The backlog
// repository is public, so a fetch works without it; the board does not.
func (r *Reconciler) auth(ctx context.Context) error {
	if r.app == nil {
		return nil
	}
	token, err := r.app.Token(ctx)
	if err != nil {
		return err
	}
	r.clone.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
	r.board.Token = token
	return nil
}

// workDir is where the backlog files are read and written: the clone, or the local directory.
func (r *Reconciler) workDir() string {
	if r.cfg.LocalDir != "" {
		return r.cfg.LocalDir
	}
	return r.cfg.CloneDir
}

// path joins a repository path onto the work directory.
func (r *Reconciler) path(parts ...string) string {
	return filepath.Join(append([]string{r.workDir()}, parts...)...)
}

// cachePath joins a name onto the cache directory.
func (r *Reconciler) cachePath(name string) string {
	return filepath.Join(r.cfg.CacheDir, name)
}

// logf is the one logger, one line per step.
func logf(format string, a ...any) {
	log.Printf(format, a...)
}
