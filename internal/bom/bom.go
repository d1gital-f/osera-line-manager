// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

// Package bom builds the OSERA BOM of a line: one POM with no code whose
// dependency management pins every promoted coordinate that made an entry of
// the line fixed, nothing else. One BOM per line, the name carries the line,
// the version is the publication date. Written to git under bom/<line>/ and
// uploaded by the line manager itself into the release repository.
package bom

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

// Group is the group every OSERA BOM is published under.
const Group = "org.finos.osera"

// Dependency is one pinned coordinate.
type Dependency struct {
	Group    string
	Artifact string
	Version  string
}

// BOM is the OSERA BOM of one line at one version.
type BOM struct {
	Line         string
	Version      string
	BuiltAt      time.Time
	Dependencies []Dependency
}

// ArtifactID is the artifact id of a line's BOM.
func ArtifactID(lineID string) string {
	return "osera-bom-" + lineID
}

// Build gathers every distinct promoted coordinate among the fixed entries.
// Two entries pinning the same library at different patched versions is an
// error, not a guess: the line manager reports it and writes nothing.
func Build(line book.Line, fixed []status.FixedEntry, version string) (*BOM, error) {
	// 1. one dependency per distinct group:artifact
	seen := map[string]Dependency{}
	for _, entry := range fixed {
		dep, err := parseCoordinate(entry.Coordinate)
		if err != nil {
			return nil, fmt.Errorf("entry %s: %w", entry.CVE, err)
		}
		key := dep.Group + ":" + dep.Artifact
		previous, known := seen[key]
		if known && previous.Version != dep.Version {
			return nil, fmt.Errorf("%s is pinned at %s and at %s on %s, one version per library", key, previous.Version, dep.Version, line.ID)
		}
		seen[key] = dep
	}

	// 2. in a stable order
	var deps []Dependency
	for _, dep := range seen {
		deps = append(deps, dep)
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Group != deps[j].Group {
			return deps[i].Group < deps[j].Group
		}
		return deps[i].Artifact < deps[j].Artifact
	})
	return &BOM{Line: line.ID, Version: version, BuiltAt: time.Now().UTC(), Dependencies: deps}, nil
}

// Version is the publication date, YYYY.MM.DD, with .2, .3 when that date is
// already taken among the existing versions.
func Version(now time.Time, existing []string) string {
	// 1. the date
	base := now.UTC().Format("2006.01.02")
	taken := map[string]bool{}
	for _, v := range existing {
		taken[v] = true
	}
	if !taken[base] {
		return base
	}

	// 2. the next free suffix
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s.%d", base, n)
		if !taken[candidate] {
			return candidate
		}
	}
}

// Coordinate is the BOM as a bank writes it in the consume column, group:artifact@version.
func (b *BOM) Coordinate() string {
	return fmt.Sprintf("%s:%s@%s", Group, ArtifactID(b.Line), b.Version)
}

// Path is where the POM sits in a Maven repository, relative to its root.
func (b *BOM) Path() string {
	return fmt.Sprintf("%s/%s/%s/%s-%s.pom", strings.ReplaceAll(Group, ".", "/"), ArtifactID(b.Line), b.Version, ArtifactID(b.Line), b.Version)
}

// The POM as XML.
type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type pom struct {
	XMLName      xml.Name        `xml:"project"`
	Xmlns        string          `xml:"xmlns,attr"`
	ModelVersion string          `xml:"modelVersion"`
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Version      string          `xml:"version"`
	Packaging    string          `xml:"packaging"`
	Name         string          `xml:"name"`
	Dependencies []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
}

// Write writes the POM: the declaration, one comment saying what it is and
// when it was built, then the project.
func (b *BOM) Write(w io.Writer) error {
	// 1. the declaration and the comment
	header := fmt.Sprintf("%s\n<!--\n  The OSERA BOM of the %s line, built %s by the line manager.\n  Every promoted patched version on the line, nothing else. Import it above the line's own dependency list.\n-->\n",
		xml.Header[:len(xml.Header)-1], b.Line, b.BuiltAt.UTC().Format(time.RFC3339))
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}

	// 2. the project
	p := pom{
		Xmlns:        "http://maven.apache.org/POM/4.0.0",
		ModelVersion: "4.0.0",
		GroupID:      Group,
		ArtifactID:   ArtifactID(b.Line),
		Version:      b.Version,
		Packaging:    "pom",
		Name:         "OSERA BOM for " + b.Line,
	}
	for _, dep := range b.Dependencies {
		p.Dependencies = append(p.Dependencies, pomDependency{GroupID: dep.Group, ArtifactID: dep.Artifact, Version: dep.Version})
	}
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	if err := encoder.Encode(p); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// Bytes is the POM as bytes.
func (b *BOM) Bytes() ([]byte, error) {
	var sb strings.Builder
	if err := b.Write(&sb); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// Upload puts the POM and its checksums into the release repository, the way
// a Maven deploy does, with the line manager's own account.
func Upload(ctx context.Context, client *releases.Client, repository string, b *BOM) error {
	// 1. the bytes and their checksums
	raw, err := b.Bytes()
	if err != nil {
		return err
	}
	sha := sha1.Sum(raw)
	md := md5.Sum(raw)

	// 2. three files, the POM first
	path := b.Path()
	if err := client.Put(ctx, repository, path, raw, "application/xml"); err != nil {
		return fmt.Errorf("uploading the BOM of %s: %w", b.Line, err)
	}
	if err := client.Put(ctx, repository, path+".sha1", []byte(hex.EncodeToString(sha[:])), "text/plain"); err != nil {
		return fmt.Errorf("uploading the BOM checksum of %s: %w", b.Line, err)
	}
	if err := client.Put(ctx, repository, path+".md5", []byte(hex.EncodeToString(md[:])), "text/plain"); err != nil {
		return fmt.Errorf("uploading the BOM checksum of %s: %w", b.Line, err)
	}
	return nil
}

// parseCoordinate reads group:artifact@version.
func parseCoordinate(s string) (Dependency, error) {
	name, version, found := strings.Cut(s, "@")
	if !found || version == "" {
		return Dependency{}, fmt.Errorf("coordinate %q has no version", s)
	}
	group, artifact, found := strings.Cut(name, ":")
	if !found || group == "" || artifact == "" {
		return Dependency{}, fmt.Errorf("coordinate %q is not group:artifact@version", s)
	}
	return Dependency{Group: group, Artifact: artifact, Version: version}, nil
}
