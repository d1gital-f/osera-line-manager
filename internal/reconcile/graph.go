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
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/graph"
)

// graphPath is where a line's Maven graph lives in the repository.
func graphPath(lineID string) string {
	return filepath.ToSlash(filepath.Join("graphs", lineID, "maven.cdx.json"))
}

// needsGraph says whether the line's graph must be built: the file is missing,
// it was built from another anchor or with another roots rule, or it carries
// unresolved nodes. A finished graph from the same anchor and rule is kept.
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

	// 5. the roots rule and the declared components the line gives today; a graph built with others is rebuilt
	rule, err := graph.RuleFor(anchor, ln.Components)
	if err != nil {
		return false, err
	}
	if g.RootsRule != rule.String() {
		return true, nil
	}
	if g.Declared != graph.Declared(rule) {
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
		highf("%s: graph kept, built from the same anchor %s and the same rule", ln.ID, ln.Anchor)
		return nil
	}
	if ln.Ecosystem != "maven" {
		Lowf("%s: ecosystem %q has no resolver yet, the graph is not built", ln.ID, ln.Ecosystem)
		return nil
	}

	// 2. the resolve, inside the pod, one fresh directory per probe under the cache
	anchor, err := book.ParseAnchor(ln.Anchor)
	if err != nil {
		return err
	}
	rule, err := graph.RuleFor(anchor, ln.Components)
	if err != nil {
		return err
	}
	if rule.Wide() {
		logf("%s: building the dependency graph from %s, no components declared, every managed artifact is a root", ln.ID, anchor)
	} else {
		logf("%s: building the dependency graph from %s, the roots in the groups %s", ln.ID, anchor, strings.Join(rule.Groups, ", "))
	}
	started := r.now()
	r.resolver.Progress = func(done, nodes, depth int) {
		if done == 0 {
			logf("%s: %d roots, %d libraries per Maven run, %d runs at a time", ln.ID, nodes, r.resolver.BatchSize, r.resolver.Workers)
			return
		}
		highf("%s: %d libraries resolved so far, %d known, now at depth %d", ln.ID, done, nodes, depth+1)
	}
	work := r.cachePath(filepath.Join("resolve", ln.ID))
	err = os.MkdirAll(work, 0o755)
	if err != nil {
		return err
	}
	g, err := r.resolver.Resolve(ctx, ln.ID, anchor, rule, work)
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
	if len(g.Pins) > 0 {
		var pins []string
		for _, pin := range g.Pins {
			pins = append(pins, pin.String())
		}
		logf("%s: the declared components pin %s", ln.ID, strings.Join(pins, ", "))
	}
	logf("%s: graph written by %s, %d libraries, %d roots, %d unresolved, in %s", ln.ID, g.Method, len(g.Components), len(g.Roots), len(g.Unresolved), seconds(r.now().Sub(started)))
	for key, why := range g.Unresolved {
		highf("%s: unresolved %s: %s", ln.ID, key, why)
	}
	return r.stage(p, ln.ID, graphPath(ln.ID), raw)
}

// filepathDir is filepath.Dir, named so pass.go reads without the import.
func filepathDir(path string) string {
	return filepath.Dir(path)
}
