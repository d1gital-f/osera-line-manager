// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package graph turns a line's anchor into its dependency graph and keeps it as
// a CycloneDX file. The resolve runs Maven as a subprocess inside the process,
// no Kubernetes Job, no shared volume (Francesco, 14 Sept 2026): every artifact
// the anchor manages is a root, each root is resolved as the single dependency
// of a throwaway POM with the anchor imported, breadth first until nothing new
// appears, compile and runtime scopes only, one fresh directory per probe. The
// method is the one that built the 725 row Wave 1 graph.
package graph

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// Component is one coordinate of the graph.
type Component struct {
	Group      string
	Artifact   string
	Version    string
	Classifier string
	// Type is the Maven type, jar when empty.
	Type string
}

// Key is group:artifact:version, with the classifier when there is one, the graph's node id.
func (c Component) Key() string {
	k := c.Group + ":" + c.Artifact + ":" + c.Version
	if c.Classifier != "" {
		k += ":" + c.Classifier
	}
	return k
}

// PURL is the package URL, pkg:maven/group/artifact@version, with the
// classifier and a non jar type as qualifiers, the version percent encoded.
func (c Component) PURL() string {
	p := "pkg:maven/" + c.Group + "/" + c.Artifact + "@" + url.PathEscape(c.Version)
	var q []string
	if c.Classifier != "" {
		q = append(q, "classifier="+url.QueryEscape(c.Classifier))
	}
	if c.Type != "" && c.Type != "jar" {
		q = append(q, "type="+url.QueryEscape(c.Type))
	}
	if len(q) > 0 {
		p += "?" + strings.Join(q, "&")
	}
	return p
}

// String is group:artifact@version.
func (c Component) String() string {
	return c.Group + ":" + c.Artifact + "@" + c.Version
}

// Graph is the line's dependency closure.
type Graph struct {
	LineID string
	Anchor book.Anchor
	// Components, sorted by key, each coordinate once.
	Components []Component
	// Roots are the keys the anchor manages, what the resolve started from.
	Roots []string
	// Dependencies maps a component key to the keys it depends on, direct only.
	Dependencies map[string][]string
	// Unresolved maps a key to why Maven could not resolve it; its edges were read from its POM instead.
	Unresolved map[string]string
}

// component finds one by key.
func (g *Graph) component(key string) (Component, bool) {
	for _, c := range g.Components {
		if c.Key() == key {
			return c, true
		}
	}
	return Component{}, false
}

// sortAll puts the graph in a stable order.
func (g *Graph) sortAll() {
	sort.Slice(g.Components, func(i, j int) bool {
		return g.Components[i].Key() < g.Components[j].Key()
	})
	sort.Strings(g.Roots)
	for k := range g.Dependencies {
		sort.Strings(g.Dependencies[k])
	}
}

// errorf is fmt.Errorf with the package name in front.
func errorf(format string, a ...any) error {
	return fmt.Errorf("graph: "+format, a...)
}
