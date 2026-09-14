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

// PinsProperty is the name of the metadata property recording the version pins the
// declared components imposed on their groups.
const PinsProperty = "osera:pins"

// ComponentsProperty is the name of the metadata property recording the declared
// components a graph was built for, so a changed component version rebuilds it.
const ComponentsProperty = "osera:components"

// Pin is a version override a declared component imposes on its whole group: every
// managed artifact of Group at version From is taken at version To instead. The Wave 1
// line declares spring-core 5.3.39 while Boot 2.7.18 manages 5.3.31, so the whole
// Spring Framework moves to 5.3.39, the way a bank's build sets it.
type Pin struct {
	Group string
	From  string
	To    string
}

// String is group:from>to.
func (p Pin) String() string {
	return p.Group + ":" + p.From + ">" + p.To
}

// pinsFor derives the pins from the managed list: one per declared component the anchor
// manages at another version, once per group and version pair.
func pinsFor(managed []Component, rule Rule) []Pin {
	// 1. the managed version of every artifact
	managedVersion := map[string]string{}
	for _, c := range managed {
		managedVersion[c.Group+":"+c.Artifact] = c.Version
	}

	// 2. a declared component managed at another version pins its group
	var pins []Pin
	seen := map[string]bool{}
	for _, c := range rule.Components {
		from, found := managedVersion[c.Group+":"+c.Artifact]
		if !found || from == c.Version {
			continue
		}
		pin := Pin{Group: c.Group, From: from, To: c.Version}
		if seen[pin.String()] {
			continue
		}
		seen[pin.String()] = true
		pins = append(pins, pin)
	}
	return pins
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
	for _, c := range rule.Components {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, " ")
}

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
