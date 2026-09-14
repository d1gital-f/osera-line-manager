// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/graph"
)

// graphPath is where a line's Maven graph lives in the repository.
func graphPath(lineID string) string {
	return filepath.ToSlash(filepath.Join("graphs", lineID, "maven.cdx.json"))
}

// needsGraph says whether the line's graph must be built: the file is missing,
// or it was built from another anchor. A present graph from the same anchor
// is kept.
func needsGraph(dir string, ln book.Line) (bool, error) {
	// 1. the anchor as declared
	anchor, err := book.ParseAnchor(ln.Anchor)
	if err != nil {
		return false, fmt.Errorf("line %s: %w", ln.ID, err)
	}

	// 2. the file, if any
	g, err := graph.Read(filepath.Join(dir, filepath.FromSlash(graphPath(ln.ID))))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return true, nil
	}

	// 3. the same line and the same anchor
	err = graph.Check(g, ln.ID, anchor)
	if err != nil {
		return true, nil
	}

	// 4. a graph with unresolved nodes is not finished: built again until every probe answers
	if len(g.Unresolved) > 0 {
		return true, nil
	}
	return false, nil
}

// ensureGraph resolves the line's graph when needed and stages the file.
func (r *Reconciler) ensureGraph(ctx context.Context, p *pass, ln book.Line) error {
	// 1. the decision
	needed, err := needsGraph(r.workDir(), ln)
	if err != nil {
		return err
	}
	if !needed {
		logf("line %s: graph present for %s, kept", ln.ID, ln.Anchor)
		return nil
	}
	if ln.Ecosystem != "maven" {
		logf("line %s: ecosystem %q has no resolver yet, the graph is not built", ln.ID, ln.Ecosystem)
		return nil
	}

	// 2. the resolve, inside the pod, one fresh directory per probe under the cache
	anchor, err := book.ParseAnchor(ln.Anchor)
	if err != nil {
		return err
	}
	logf("line %s: resolving %s", ln.ID, anchor)
	work := r.cachePath(filepath.Join("resolve", ln.ID))
	err = os.MkdirAll(work, 0o755)
	if err != nil {
		return err
	}
	g, err := r.resolver.Resolve(ctx, ln.ID, anchor, work)
	if err != nil {
		return fmt.Errorf("line %s: %w", ln.ID, err)
	}

	// 3. the file, written and staged
	path := r.path(filepath.FromSlash(graphPath(ln.ID)))
	err = os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return err
	}
	err = graph.Write(path, g, r.now())
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	logf("line %s: graph built, %d components", ln.ID, len(g.Components))
	return r.stage(p, ln.ID, graphPath(ln.ID), raw)
}

// filepathDir is filepath.Dir, named so pass.go reads without the import.
func filepathDir(path string) string {
	return filepath.Dir(path)
}
