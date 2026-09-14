// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// A POM read from a repository: enough of the model to know the packaging,
// the parent chain, the properties, what it manages and what it declares.

// Central is where Maven artifacts live unless the line says otherwise.
const Central = "https://repo1.maven.org/maven2/"

// pom is the XML as read.
type pom struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Packaging  string `xml:"packaging"`
	Parent     struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Any []xmlProperty `xml:",any"`
	} `xml:"properties"`
	DependencyManagement struct {
		Dependencies []dependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []dependency `xml:"dependencies>dependency"`
}

// xmlProperty is one element under properties, whatever its name.
type xmlProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// dependency is one declared or managed dependency.
type dependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

// model is a POM with its parent chain read and its properties resolved.
type model struct {
	Group     string
	Artifact  string
	Version   string
	Packaging string
	// Managed is dependencyManagement across the chain, imports left out, versions resolved.
	Managed []Component
	// Declared is the POM's own compile and runtime, non optional dependencies, versions resolved.
	Declared []Component
}

// fetchPOM reads one POM from the repositories, in order, the first that has it.
func (r *Resolver) fetchPOM(ctx context.Context, group, artifact, version string) ([]byte, error) {
	path := strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
	var last error
	for _, base := range r.repositories() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/"+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "osera-line-manager")
		if srv, found := r.server(base); found {
			req.SetBasicAuth(srv.User, srv.Password)
		}
		resp, err := r.HTTP.Do(req)
		if err != nil {
			last = err
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return raw, nil
		}
		last = errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	if last == nil {
		last = errorf("%s: no repository", path)
	}
	return nil, last
}

// readModel reads a POM and its parents, resolves the properties, and returns the model.
func (r *Resolver) readModel(ctx context.Context, group, artifact, version string) (*model, error) {
	// 1. the chain, child first
	var chain []pom
	g, a, v := group, artifact, version
	for i := 0; i < 20 && g != "" && a != "" && v != ""; i++ {
		raw, err := r.fetchPOM(ctx, g, a, v)
		if err != nil {
			if len(chain) == 0 {
				return nil, err
			}
			break
		}
		var p pom
		err = xml.Unmarshal(raw, &p)
		if err != nil {
			return nil, errorf("%s:%s:%s: %w", g, a, v, err)
		}
		chain = append(chain, p)
		g, a, v = p.Parent.GroupID, p.Parent.ArtifactID, p.Parent.Version
	}
	child := chain[0]

	// 2. the properties, parents first so the child wins
	props := map[string]string{}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, pr := range chain[i].Properties.Any {
			props[pr.XMLName.Local] = strings.TrimSpace(pr.Value)
		}
	}
	m := &model{Group: firstOf(child.GroupID, child.Parent.GroupID), Artifact: child.ArtifactID, Version: firstOf(child.Version, child.Parent.Version), Packaging: firstOf(child.Packaging, "jar")}
	props["project.version"] = m.Version
	props["project.groupId"] = m.Group
	props["project.artifactId"] = m.Artifact
	props["pom.version"] = m.Version
	props["pom.groupId"] = m.Group

	// 3. what the chain manages, parents first so the child wins, imports left out
	managed := map[string]Component{}
	var order []string
	for i := len(chain) - 1; i >= 0; i-- {
		for _, d := range chain[i].DependencyManagement.Dependencies {
			if d.Scope == "import" {
				continue
			}
			c := Component{Group: subst(d.GroupID, props), Artifact: subst(d.ArtifactID, props), Version: subst(d.Version, props), Classifier: d.Classifier, Type: firstOf(d.Type, "jar")}
			key := c.Group + ":" + c.Artifact + ":" + c.Classifier + ":" + c.Type
			if _, seen := managed[key]; !seen {
				order = append(order, key)
			}
			managed[key] = c
		}
	}
	for _, key := range order {
		c := managed[key]
		if c.Version == "" || strings.Contains(c.Version, "${") {
			continue
		}
		m.Managed = append(m.Managed, c)
	}

	// 4. what the POM itself declares, compile and runtime, not optional, version from the management when absent
	for _, d := range child.Dependencies {
		scope := firstOf(d.Scope, "compile")
		if scope != "compile" && scope != "runtime" {
			continue
		}
		if strings.TrimSpace(d.Optional) == "true" {
			continue
		}
		c := Component{Group: subst(d.GroupID, props), Artifact: subst(d.ArtifactID, props), Version: subst(d.Version, props), Classifier: d.Classifier, Type: firstOf(d.Type, "jar")}
		if c.Version == "" {
			if mc, found := managed[c.Group+":"+c.Artifact+":"+c.Classifier+":"+c.Type]; found {
				c.Version = mc.Version
			}
		}
		if c.Version == "" || strings.Contains(c.Version, "${") {
			continue
		}
		m.Declared = append(m.Declared, c)
	}
	return m, nil
}

var property = regexp.MustCompile(`\$\{([^}]+)\}`)

// subst replaces ${name} with the property, a few rounds deep.
func subst(s string, props map[string]string) string {
	for i := 0; i < 5; i++ {
		next := property.ReplaceAllStringFunc(s, func(m string) string {
			name := m[2 : len(m)-1]
			if v, found := props[name]; found {
				return v
			}
			return m
		})
		if next == s {
			break
		}
		s = next
	}
	return strings.TrimSpace(s)
}

func firstOf(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
