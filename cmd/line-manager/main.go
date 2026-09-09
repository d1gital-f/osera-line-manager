// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// line-manager reports whether a supported line is remediated. Two ways to run it:
// "status" computes one record from local files, "run" is the loop against the
// published backlog repository.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/ledger"
	"github.com/d1gital-f/osera-line-manager/internal/reconcile"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// version is set at build time.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: line-manager status|run [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "status":
		statusCommand(os.Args[2:])
	case "run":
		runCommand(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: line-manager status|run [flags]")
		os.Exit(2)
	}
}

// statusCommand: one record per line from local files, printed.
func statusCommand(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	bookPath := fs.String("book", "cve-backlog.json", "the order book")
	linesPath := fs.String("lines", "supported-lines.csv", "the supported lines")
	ledgerPath := fs.String("ledger", "", "a ledger export, empty for none")
	bookVersion := fs.String("book-version", "", "the tag the book was published under")
	fail(fs.Parse(args))

	b, err := book.Read(*bookPath)
	fail(err)
	lines, err := book.ReadLines(*linesPath)
	fail(err)
	l := ledger.Empty()
	if *ledgerPath != "" {
		l, err = ledger.Read(*ledgerPath)
		fail(err)
	}
	asOf := time.Now().UTC().Format(time.RFC3339)
	var records []status.Record
	for _, ln := range lines {
		records = append(records, status.Compute(status.Inputs{
			Line: ln.ID, BookVersion: *bookVersion, AsOf: asOf, Book: b, Ledger: l, BacklogRepository: "backlog",
		}))
	}
	out, err := json.MarshalIndent(records, "", "  ")
	fail(err)
	fmt.Println(string(out))
}

// runCommand: the loop, plus a health endpoint for the cluster.
func runCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	owner := fs.String("owner", "finos-osera", "the organisation or account that holds the backlog repository")
	repo := fs.String("backlog-repo", "backlog", "the backlog repository")
	ledgerPath := fs.String("ledger", "", "a ledger export, empty for none")
	outDir := fs.String("out", "/data/status", "where the status records are written")
	interval := fs.Duration("interval", 10*time.Minute, "time between passes")
	queryOSV := fs.Bool("osv", true, "ask OSV for advisories the book does not carry")
	queryIssues := fs.Bool("issues", true, "ask GitHub where each CVE's issue lives")
	once := fs.Bool("once", false, "one pass, then exit")
	local := fs.String("local", "", "a directory with cve-backlog.json and supported-lines.csv, read instead of GitHub")
	localVersion := fs.String("book-version", "", "the book version to record on a local run, the directory name when empty")
	writeLines := fs.String("write-lines", "", "a supported-lines.csv to rewrite with the status columns after each pass")
	fail(fs.Parse(args))

	cfg := reconcile.Config{
		Owner:        *owner,
		BacklogRepo:  *repo,
		LedgerPath:   *ledgerPath,
		OutDir:       *outDir,
		GitHubToken:  os.Getenv("GITHUB_TOKEN"),
		QueryOSV:     *queryOSV,
		QueryIssues:  *queryIssues,
		LocalDir:     *local,
		LocalVersion: *localVersion,
		LinesPath:    *writeLines,
	}
	log.Printf("line-manager %s watching %s/%s every %s", version, cfg.Owner, cfg.BacklogRepo, *interval)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *once {
		_, err := reconcile.Once(ctx, cfg)
		fail(err)
		return
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.Handle("GET /status/", http.StripPrefix("/status/", http.FileServer(http.Dir(*outDir))))
		server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()
	reconcile.Loop(ctx, cfg, *interval)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
