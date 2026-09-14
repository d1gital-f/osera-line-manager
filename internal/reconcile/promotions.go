// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/board"
	"github.com/d1gital-f/osera-line-manager/internal/bom"
	"github.com/d1gital-f/osera-line-manager/internal/intent"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// readBoard reads the organisation board once. Local mode has no board.
func (r *Reconciler) readBoard(ctx context.Context) ([]status.Issue, error) {
	if r.board == nil {
		return nil, nil
	}
	cards, err := r.board.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the board: %w", err)
	}
	issues := board.Issues(cards, r.cfg.Repo)
	logf("%s", boardSummary(issues, r.cfg.Repo))
	return issues, nil
}

// evidenceCache remembers the evidence read for each coordinate across passes,
// so a coordinate is read once ever. None marks a coordinate without evidence.
type evidenceCache struct {
	Evidence map[string]*releases.Evidence `json:"evidence"`
	None     map[string]bool               `json:"none"`
}

// readPromotions lists the release repository once and reads the evidence next
// to every patched coordinate not yet known. The line manager's own BOMs are in
// the listing too; they fix nothing and are skipped, the intent note says which
// one it just uploaded.
func (r *Reconciler) readPromotions(ctx context.Context, p *pass) ([]status.Promotion, error) {
	if r.nexus == nil {
		return nil, nil
	}

	// 1. the listing
	coords, err := r.nexus.Promoted(ctx, r.cfg.Nexus.ReleaseRepository)
	if err != nil {
		return nil, fmt.Errorf("reading the release repository: %w", err)
	}

	// 2. the cache
	cache := evidenceCache{Evidence: map[string]*releases.Evidence{}, None: map[string]bool{}}
	raw, err := os.ReadFile(r.cachePath("evidence.json"))
	if err == nil {
		err = json.Unmarshal(raw, &cache)
		if err != nil {
			return nil, fmt.Errorf("reading the evidence cache: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// 3. one promotion per coordinate, the evidence read once
	var out []status.Promotion
	read := 0
	patched := 0
	withEvidence := 0
	for _, c := range coords {
		if ownUpload(p.own, c) || c.Group == bom.Group {
			out = append(out, status.Promotion{Coordinate: c})
			continue
		}
		if !c.Patched() {
			out = append(out, status.Promotion{Coordinate: c})
			continue
		}
		patched++
		key := c.String()
		ev, known := cache.Evidence[key]
		if !known && !cache.None[key] {
			ev, err = r.nexus.Evidence(ctx, r.cfg.Nexus.ReleaseRepository, c)
			read++
			if err != nil {
				if !errors.Is(err, releases.ErrNoEvidence) {
					return nil, err
				}
				cache.None[key] = true
				highf("release repository: %s has no evidence file", key)
			} else {
				cache.Evidence[key] = ev
			}
		}
		if ev != nil {
			withEvidence++
			highf("release repository: %s fixes %s, producer %s", key, strings.Join(ev.CVEs(), ", "), ev.Producer)
		}
		out = append(out, status.Promotion{Coordinate: c, Evidence: ev})
	}

	// 4. the cache saved when anything was read
	if read > 0 {
		raw, err = json.MarshalIndent(cache, "", "  ")
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(r.cachePath("evidence.json"), raw, 0o644)
		if err != nil {
			return nil, err
		}
	}
	logf("release repository: %d coordinates, %d patched, %d with an evidence file, %d read this pass", len(coords), patched, withEvidence, read)
	return out, nil
}

// ownUpload says whether a coordinate is the BOM the line manager itself just
// uploaded, as the intent note remembers it.
func ownUpload(own *intent.Intent, c releases.Coordinate) bool {
	if own == nil {
		return false
	}
	return own.Kind == "bom" && own.Ref == c.String()
}
