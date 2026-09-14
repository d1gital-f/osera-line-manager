// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// line-manager reports whether a supported line is fixed. Two commands:
// "status" computes one record per line from local files and prints them,
// "run" is the loop against the backlog repository, the board and the release
// repository. Every setting of "run" is read from the environment first, so a
// Deployment sets names and no flags; a flag of the same meaning overrides it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/reconcile"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// version is set at build time.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "status":
		statusCommand(os.Args[2:])
	case "run":
		runCommand(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: line-manager status|run [flags]")
	os.Exit(2)
}

// statusCommand: one record per line from local files, printed. No board, no
// release repository: what the files say, and the word that follows from it.
func statusCommand(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	bookPath := fs.String("book", "cve-backlog.json", "the backlog")
	linesPath := fs.String("lines", "supported-lines.csv", "the supported lines")
	bookVersion := fs.String("book-version", "", "the tag the backlog was published under")
	fail(fs.Parse(args))

	// 1. the files
	b, err := book.Read(*bookPath)
	fail(err)
	lines, err := book.ReadLines(*linesPath)
	fail(err)

	// 2. one record per line
	asOf := time.Now().UTC().Format(time.RFC3339)
	var records []status.Record
	for _, ln := range lines {
		records = append(records, status.Compute(status.Inputs{
			Line:              ln,
			BookVersion:       *bookVersion,
			AsOf:              asOf,
			Book:              b,
			BacklogRepository: "backlog",
			Consume:           ln.Consume,
		}))
	}

	// 3. printed
	out, err := json.MarshalIndent(records, "", "  ")
	fail(err)
	fmt.Println(string(out))
}

// runCommand: the loop. Environment first, flags override.
func runCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	owner := fs.String("owner", env("GITHUB_OWNER", "dev-finos-osera-forks"), "the organisation that holds the backlog repository (GITHUB_OWNER)")
	repoName := fs.String("repo", env("GITHUB_REPO", "backlog"), "the backlog repository (GITHUB_REPO)")
	appID := fs.Int64("app-id", envInt("GITHUB_APP_ID", 0), "the GitHub App id (GITHUB_APP_ID)")
	installationID := fs.Int64("installation-id", envInt("GITHUB_INSTALLATION_ID", 0), "the App's installation id on the organisation (GITHUB_INSTALLATION_ID)")
	keyFile := fs.String("app-key-file", env("GITHUB_APP_KEY_FILE", "/secrets/github/app-key.pem"), "the App's private key, PEM (GITHUB_APP_KEY_FILE)")
	boardNumber := fs.Int("board-number", int(envInt("BOARD_NUMBER", 1)), "the organisation project number of the board (BOARD_NUMBER)")
	nexusURL := fs.String("nexus-url", env("NEXUS_URL", ""), "the Nexus address (NEXUS_URL)")
	nexusUser := fs.String("nexus-user", env("NEXUS_USER", "line-manager"), "the Nexus account (NEXUS_USER)")
	releaseRepository := fs.String("release-repository", env("NEXUS_RELEASE_REPOSITORY", "osera-releases-maven-01"), "the release repository (NEXUS_RELEASE_REPOSITORY)")
	cloneDir := fs.String("clone-dir", env("CLONE_DIR", "/data/backlog"), "where the clone lives (CLONE_DIR)")
	cacheDir := fs.String("cache-dir", env("CACHE_DIR", "/data/cache"), "the caches, the stamps and the intent note (CACHE_DIR)")
	interval := fs.Duration("interval", envDuration("INTERVAL", 10*time.Minute), "time between passes (INTERVAL)")
	rescan := fs.Duration("rescan-interval", envDuration("RESCAN_INTERVAL", 7*24*time.Hour), "time between two scans of one line (RESCAN_INTERVAL)")
	devAdvisories := fs.String("dev-advisories", env("DEV_ADVISORIES", ""), "the dev only advisory file inside the repository, empty in production (DEV_ADVISORIES)")
	listen := fs.String("listen", env("LISTEN", ":8080"), "the address of the health, status and webhook server (LISTEN)")
	mavenWorkers := fs.Int("maven-workers", envInt("MAVEN_WORKERS", 4), "how many Maven probes run at once (MAVEN_WORKERS)")
	mavenRepositories := fs.String("maven-repositories", env("MAVEN_REPOSITORIES", ""), "the repositories the resolver reads, comma separated, Central when empty; one under the Nexus address is read with the Nexus account (MAVEN_REPOSITORIES)")
	dry := fs.Bool("dry", envBool("DRY", false), "compute and log, write nothing to GitHub or Nexus (DRY)")
	once := fs.Bool("once", false, "one pass, then exit")
	local := fs.String("local", "", "a directory with the backlog files, read instead of the clone; no GitHub, no Nexus")
	localVersion := fs.String("book-version", "", "the book version to record on a local run")
	fail(fs.Parse(args))

	// 1. the secrets, from the environment only
	cfg := reconcile.Config{
		Owner:             *owner,
		Repo:              *repoName,
		CloneDir:          *cloneDir,
		App:               reconcile.AppConfig{ID: *appID, InstallationID: *installationID, KeyFile: *keyFile},
		BoardNumber:       *boardNumber,
		Nexus:             reconcile.NexusConfig{URL: *nexusURL, User: *nexusUser, Password: os.Getenv("NEXUS_PASSWORD"), ReleaseRepository: *releaseRepository},
		WebhookSecret:     os.Getenv("WEBHOOK_SECRET"),
		MavenRepositories: splitList(*mavenRepositories),
		MavenWorkers:      *mavenWorkers,
		CacheDir:          *cacheDir,
		Interval:          *interval,
		RescanInterval:    *rescan,
		DevAdvisories:     *devAdvisories,
		Dry:               *dry,
		Listen:            *listen,
		LocalDir:          *local,
		LocalVersion:      *localVersion,
	}
	if cfg.LocalDir == "" {
		if cfg.App.ID == 0 || cfg.App.InstallationID == 0 {
			fail(fmt.Errorf("GITHUB_APP_ID and GITHUB_INSTALLATION_ID are required"))
		}
		if cfg.Nexus.URL == "" {
			fail(fmt.Errorf("NEXUS_URL is required"))
		}
	}
	log.Printf("line-manager %s: %s/%s, board %d, %s, every %s, rescan every %s, dry %v", version, cfg.Owner, cfg.Repo, cfg.BoardNumber, cfg.Nexus.URL, cfg.Interval, cfg.RescanInterval, cfg.Dry)

	// 2. the reconciler
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	r, err := reconcile.New(ctx, cfg)
	fail(err)

	// 3. one pass, or the loop
	if *once || cfg.LocalDir != "" {
		_, err = r.Once(ctx)
		fail(err)
		return
	}
	fail(r.Run(ctx))
}

// env reads a string setting, the fallback when unset.
func env(name, fallback string) string {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	return v
}

// envInt reads an integer setting, the fallback when unset or not a number.
func envInt(name string, fallback int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		fail(fmt.Errorf("%s: %w", name, err))
	}
	return n
}

// envDuration reads a duration setting, 10m style.
func envDuration(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fail(fmt.Errorf("%s: %w", name, err))
	}
	return d
}

// envBool reads a true or false setting.
func envBool(name string, fallback bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		fail(fmt.Errorf("%s: %w", name, err))
	}
	return b
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// splitList turns a comma separated flag into its items, blanks dropped.
func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
