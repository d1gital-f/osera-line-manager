// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/releases"
)

// Run does one pass now, then one every interval and one more after every
// accepted webhook event, and serves health, the status files and the webhook
// until the context ends.
func (r *Reconciler) Run(ctx context.Context) error {
	// 1. the server: health, the status files from the clone, the webhook
	server := &http.Server{Addr: r.cfg.Listen, Handler: r.mux(), ReadHeaderTimeout: 5 * time.Second}
	serverErr := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()
	logf("listening on %s, a pass every %s", server.Addr, r.cfg.Interval)

	// 2. the ticker first, so the timer counts from the start and the log says the right
	//    time, then the first pass, then the wake ups
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	r.nextAt = r.now().Add(r.cfg.Interval)
	r.passFor(ctx, "on start, from an empty cache: every line is scanned again and every evidence file is read again")
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(shutdown)
		case err := <-serverErr:
			return err
		case <-ticker.C:
			r.nextAt = r.now().Add(r.cfg.Interval)
			r.passFor(ctx, fmt.Sprintf("on the timer (every %s)", r.cfg.Interval))
		case reason := <-r.wake:
			r.passFor(ctx, reason)
		}
	}
}

// passFor runs one pass for a reason and logs a failure instead of stopping the loop.
func (r *Reconciler) passFor(ctx context.Context, reason string) {
	_, err := r.OnceFor(ctx, reason)
	if err != nil {
		Lowf("! pass %d failed: %v", r.passes, err)
	}
}

// mux is the server: GET /healthz, GET /status/<line>.json, POST /webhook, POST /pass (a pass by hand).
func (r *Reconciler) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /status/", http.StripPrefix("/status/", http.FileServer(http.Dir(filepath.Join(r.workDir(), "status")))))
	mux.HandleFunc("POST /pass", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case r.wake <- "by hand, POST /pass":
			logf("+ a pass was asked for by hand on /pass; it starts now, or when the running one ends")
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	mux.Handle("POST /webhook", releases.Handler(r.cfg.WebhookSecret, func(ev releases.Event) {
		if ev.Repository != r.cfg.Nexus.ReleaseRepository {
			logf("! webhook from %s ignored: not the release repository", ev.Repository)
			return
		}
		logf("+ webhook from the release repository: %s %s; a pass starts now, or when the running one ends", ev.Action, ev.Coordinate)
		select {
		case r.wake <- fmt.Sprintf("on the webhook: %s %s", ev.Action, ev.Coordinate):
		default:
		}
	}))
	return mux
}
