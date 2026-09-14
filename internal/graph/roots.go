// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"sort"
	"strings"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// Rule says where a resolve starts. A line is its projects at their versions, not
// everything its anchor has an opinion about: the roots are the anchor's managed
// artifacts whose group is one of the line's component groups (the anchor's own
// group counts), plus a declared component the anchor does not manage, at its
// declared version. A line with no components falls back to every managed artifact,
// the wide graph, and says so. A jar anchor is its own single root whatever the rule.
type Rule struct {
	// Groups are the root groups, sorted, empty for the fallback.
	Groups []string
	// Components are the line's declared components, roots when the anchor does not manage them.
	Components []Component
}

// RootsProperty is the name of the metadata property recording the rule a graph was built with.
const RootsProperty = "osera:roots"

// RuleFor derives the rule from the anchor and the line's declared components.
func RuleFor(anchor book.Anchor, components []string) Rule {
	// 1. the groups: the anchor's and every component's, once each
	seen := map[string]bool{}
	var rule Rule
	for _, c := range components {
		parsed, err := book.ParseAnchor(c)
		if err != nil {
			continue
		}
		rule.Components = append(rule.Components, Component{Group: parsed.Group, Artifact: parsed.Artifact, Version: parsed.Version})
		if !seen[parsed.Group] {
			seen[parsed.Group] = true
			rule.Groups = append(rule.Groups, parsed.Group)
		}
	}

	// 2. no components, no rule: the wide graph
	if len(rule.Components) == 0 {
		return Rule{}
	}
	if !seen[anchor.Group] {
		rule.Groups = append(rule.Groups, anchor.Group)
	}
	sort.Strings(rule.Groups)
	return rule
}

// String is what the graph file records: groups:<a,b,c>, or managed for the fallback.
func (r Rule) String() string {
	if len(r.Groups) == 0 {
		return "managed"
	}
	return "groups:" + strings.Join(r.Groups, ",")
}

// Wide says the rule is the fallback, every managed artifact.
func (r Rule) Wide() bool {
	return len(r.Groups) == 0
}

// selectRoots applies the rule to the anchor's managed list: the managed artifacts in
// the root groups, then the declared components the anchor does not manage.
func selectRoots(managed []Component, rule Rule) []Component {
	// 1. the fallback: everything
	if rule.Wide() {
		return managed
	}
	inGroups := map[string]bool{}
	for _, g := range rule.Groups {
		inGroups[g] = true
	}

	// 2. the managed artifacts of the root groups, in the anchor's order
	var out []Component
	managedGA := map[string]bool{}
	for _, c := range managed {
		managedGA[c.Group+":"+c.Artifact] = true
		if inGroups[c.Group] {
			out = append(out, c)
		}
	}

	// 3. a declared component the anchor does not manage, at its declared version
	for _, c := range rule.Components {
		if managedGA[c.Group+":"+c.Artifact] {
			continue
		}
		out = append(out, c)
	}
	return out
}
