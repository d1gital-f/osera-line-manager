// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// The graph as a CycloneDX 1.6 file: metadata.component is the anchor with the
// line id as a property, components are the coordinates with their purl as
// bom-ref, dependencies are the edges. Scanners read it as it is.

// LineProperty is the name of the property carrying the line id.
const LineProperty = "osera:line"

// Version of the line manager, set by the caller for the tools block.
var ToolVersion = "dev"

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Group      string        `json:"group,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	PURL       string        `json:"purl"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxFile struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []cdxComponent `json:"components"`
		} `json:"tools"`
		Component cdxComponent `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

// Write saves the graph as CycloneDX JSON.
func Write(path string, g *Graph, now time.Time) error {
	// 1. the header
	var f cdxFile
	f.BOMFormat = "CycloneDX"
	f.SpecVersion = "1.6"
	f.SerialNumber = "urn:uuid:" + newUUID()
	f.Version = 1
	f.Metadata.Timestamp = now.UTC().Format(time.RFC3339)
	f.Metadata.Tools.Components = []cdxComponent{{Type: "application", BOMRef: "osera-line-manager", Name: "osera-line-manager", Version: ToolVersion, PURL: "pkg:github/finos-osera/osera-platform"}}

	// 2. the anchor, with the line id
	anchor := Component{Group: g.Anchor.Group, Artifact: g.Anchor.Artifact, Version: g.Anchor.Version, Type: "pom"}
	f.Metadata.Component = cdxComponent{Type: "library", BOMRef: anchor.PURL(), Group: anchor.Group, Name: anchor.Artifact, Version: anchor.Version, PURL: anchor.PURL(), Properties: []cdxProperty{{Name: LineProperty, Value: g.LineID}, {Name: RootsProperty, Value: g.RootsRule}}}

	// 3. the components and the edges, the anchor depending on the roots
	refs := map[string]string{}
	f.Components = []cdxComponent{}
	for _, c := range g.Components {
		refs[c.Key()] = c.PURL()
		comp := cdxComponent{Type: "library", BOMRef: c.PURL(), Group: c.Group, Name: c.Artifact, Version: c.Version, PURL: c.PURL()}
		if why, unresolved := g.Unresolved[c.Key()]; unresolved {
			comp.Properties = []cdxProperty{{Name: "osera:unresolved", Value: why}}
		}
		f.Components = append(f.Components, comp)
	}
	f.Dependencies = []cdxDependency{}
	var rootRefs []string
	for _, key := range g.Roots {
		rootRefs = append(rootRefs, refs[key])
	}
	f.Dependencies = append(f.Dependencies, cdxDependency{Ref: anchor.PURL(), DependsOn: nonNil(rootRefs)})
	for _, c := range g.Components {
		var on []string
		for _, key := range g.Dependencies[c.Key()] {
			on = append(on, refs[key])
		}
		f.Dependencies = append(f.Dependencies, cdxDependency{Ref: c.PURL(), DependsOn: nonNil(on)})
	}

	// 4. written
	raw, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

// Read loads a CycloneDX file back into a graph.
func Read(path string) (*Graph, error) {
	// 1. the file
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errorf("reading %s: %w", path, err)
	}
	var f cdxFile
	err = json.Unmarshal(raw, &f)
	if err != nil {
		return nil, errorf("parsing %s: %w", path, err)
	}
	if f.BOMFormat != "CycloneDX" {
		return nil, errorf("%s is not a CycloneDX file", path)
	}

	// 2. the anchor and the line
	g := &Graph{Dependencies: map[string][]string{}, Unresolved: map[string]string{}}
	g.Anchor = book.Anchor{Group: f.Metadata.Component.Group, Artifact: f.Metadata.Component.Name, Version: f.Metadata.Component.Version}
	for _, p := range f.Metadata.Component.Properties {
		if p.Name == LineProperty {
			g.LineID = p.Value
		}
		if p.Name == RootsProperty {
			g.RootsRule = p.Value
		}
	}

	// 3. the components by purl
	byRef := map[string]Component{}
	for _, c := range f.Components {
		comp := Component{Group: c.Group, Artifact: c.Name, Version: c.Version}
		comp.Classifier, comp.Type = qualifiers(c.PURL)
		byRef[c.BOMRef] = comp
		g.Components = append(g.Components, comp)
		for _, p := range c.Properties {
			if p.Name == "osera:unresolved" {
				g.Unresolved[comp.Key()] = p.Value
			}
		}
	}

	// 4. the edges, the anchor's row giving the roots
	for _, d := range f.Dependencies {
		if d.Ref == f.Metadata.Component.BOMRef {
			for _, on := range d.DependsOn {
				g.Roots = append(g.Roots, byRef[on].Key())
			}
			continue
		}
		parent, known := byRef[d.Ref]
		if !known {
			continue
		}
		var keys []string
		for _, on := range d.DependsOn {
			keys = append(keys, byRef[on].Key())
		}
		g.Dependencies[parent.Key()] = keys
	}
	g.sortAll()
	return g, nil
}

// Check says the file is the one asked for: this line, this anchor.
func Check(g *Graph, lineID string, anchor book.Anchor) error {
	if g.LineID != lineID {
		return errorf("the graph is for line %q, not %q", g.LineID, lineID)
	}
	if g.Anchor != anchor {
		return errorf("the graph was built from %s, not %s", g.Anchor, anchor)
	}
	return nil
}

// qualifiers reads the classifier and type back from a purl.
func qualifiers(purl string) (string, string) {
	i := strings.Index(purl, "?")
	if i < 0 {
		return "", "jar"
	}
	classifier := ""
	typ := "jar"
	for _, q := range strings.Split(purl[i+1:], "&") {
		kv := strings.SplitN(q, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "classifier":
			classifier = kv[1]
		case "type":
			typ = kv[1]
		}
	}
	return classifier, typ
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// newUUID is a random version 4 UUID.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
