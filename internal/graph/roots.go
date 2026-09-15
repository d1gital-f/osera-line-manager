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
// artifacts whose group is one of the line's declared groups (the anchor's own group
// counts). A line with no components falls back to every managed artifact, which for
// a project's own BOM is exactly its modules, and for a list like Boot's is the wide
// graph. A jar anchor is its own single root whatever the rule.
type Rule struct {
	// Groups are the root groups, sorted, empty for the fallback.
	Groups []string
	// Declared are the line's declared components, a group at a version each.
	Declared []book.Declared
}

// RootsProperty is the name of the metadata property recording the rule a graph was built with.
const RootsProperty = "osera:roots"

// PinsProperty is the name of the metadata property recording the version pins the
// declared components imposed on their groups.
const PinsProperty = "osera:pins"

// ComponentsProperty is the name of the metadata property recording the declared
// components a graph was built for, so a changed component version rebuilds it.
const ComponentsProperty = "osera:components"

// Pin is a version override a declared component imposes on its whole group: every
// managed artifact of Group at version From is taken at version To instead. The Wave 1
// line declares org.springframework@5.3.39 while Boot 2.7.18 manages 5.3.31, so the
// whole Spring Framework moves to 5.3.39, the way a bank's build sets it.
type Pin struct {
	Group string
	From  string
	To    string
}

// String is group:from>to.
func (p Pin) String() string {
	return p.Group + ":" + p.From + ">" + p.To
}

// pinsFor derives the pins from the managed list: one per declared group and managed
// version other than the declared one, in the managed order.
func pinsFor(managed []Component, rule Rule) []Pin {
	var pins []Pin
	seen := map[string]bool{}
	for _, d := range rule.Declared {
		for _, c := range managed {
			if c.Group != d.Group || c.Version == d.Version {
				continue
			}
			pin := Pin{Group: d.Group, From: c.Version, To: d.Version}
			if seen[pin.String()] {
				continue
			}
			seen[pin.String()] = true
			pins = append(pins, pin)
		}
	}
	return pins
}

// unmanagedGroups are the declared groups the anchor manages nothing of: they give the
// line no roots, and the build says so.
func unmanagedGroups(managed []Component, rule Rule) []string {
	present := map[string]bool{}
	for _, c := range managed {
		present[c.Group] = true
	}
	var out []string
	for _, d := range rule.Declared {
		if !present[d.Group] {
			out = append(out, d.Group)
		}
	}
	return out
}

// applyPins returns the managed list with every artifact of a pinned group at the pinned
// version, the rest untouched.
func applyPins(managed []Component, pins []Pin) []Component {
	out := make([]Component, 0, len(managed))
	for _, c := range managed {
		for _, pin := range pins {
			if c.Group == pin.Group && c.Version == pin.From {
				c.Version = pin.To
			}
		}
		out = append(out, c)
	}
	return out
}

// pinsString is what the graph file records, comma separated.
func pinsString(pins []Pin) string {
	var parts []string
	for _, p := range pins {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// parsePins reads pinsString back.
func parsePins(s string) []Pin {
	var pins []Pin
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			continue
		}
		i := strings.LastIndex(part, ":")
		j := strings.LastIndex(part, ">")
		if i < 0 || j < i {
			continue
		}
		pins = append(pins, Pin{Group: part[:i], From: part[i+1 : j], To: part[j+1:]})
	}
	return pins
}

// Declared is the declared components as the graph file records them.
func Declared(rule Rule) string {
	return componentsString(rule)
}

// componentsString is the declared components as the graph file records them.
func componentsString(rule Rule) string {
	var parts []string
	for _, d := range rule.Declared {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, " ")
}

// RuleFor derives the rule from the anchor and the line's declared components. A
// component that does not read as group@version is an error: the line is skipped and
// the pass says why, rather than building the wrong graph.
func RuleFor(anchor book.Anchor, components []string) (Rule, error) {
	// 1. the groups: every component's and the anchor's, once each
	seen := map[string]bool{}
	var rule Rule
	for _, c := range components {
		d, err := book.ParseDeclared(c)
		if err != nil {
			return Rule{}, err
		}
		rule.Declared = append(rule.Declared, d)
		if !seen[d.Group] {
			seen[d.Group] = true
			rule.Groups = append(rule.Groups, d.Group)
		}
	}

	// 2. no components, no rule: the wide graph
	if len(rule.Declared) == 0 {
		return Rule{}, nil
	}
	if !seen[anchor.Group] {
		rule.Groups = append(rule.Groups, anchor.Group)
	}
	sort.Strings(rule.Groups)
	return rule, nil
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
// the root groups, in the anchor's order; the fallback takes everything.
func selectRoots(managed []Component, rule Rule) []Component {
	// 1. the fallback: everything
	if rule.Wide() {
		return managed
	}
	inGroups := map[string]bool{}
	for _, g := range rule.Groups {
		inGroups[g] = true
	}

	// 2. the managed artifacts of the root groups
	var out []Component
	for _, c := range managed {
		if inGroups[c.Group] {
			out = append(out, c)
		}
	}
	return out
}
