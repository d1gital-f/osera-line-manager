// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// The pins a line's components impose: spring-core 5.3.39 over the 5.3.31 Boot manages
// moves the whole org.springframework group; security the same; a component the
// anchor does not manage pins nothing and stays a root at its version.
func TestPinsFor(t *testing.T) {
	managed := []Component{
		{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.31"},
		{Group: "org.springframework", Artifact: "spring-web", Version: "5.3.31"},
		{Group: "org.springframework", Artifact: "spring-legacy", Version: "4.3.30"},
		{Group: "org.springframework.security", Artifact: "spring-security-core", Version: "5.7.11"},
		{Group: "org.apache.tomcat.embed", Artifact: "tomcat-embed-core", Version: "9.0.83"},
	}
	boot := book.Anchor{Group: "org.springframework.boot", Artifact: "spring-boot-dependencies", Version: "2.7.18"}
	rule := RuleFor(boot, []string{"org.springframework:spring-core@5.3.39", "org.springframework.security:spring-security-core@5.7.11", "org.example:extra@9.9"})

	// 1. one pin, spring only: security is managed at the declared version, extra is not managed
	pins := pinsFor(managed, rule)
	if len(pins) != 1 || pins[0].String() != "org.springframework:5.3.31>5.3.39" {
		t.Fatalf("pins %v", pins)
	}

	// 2. applied: spring-core and spring-web move, the 4.3.30 artifact and the others stay
	pinned := applyPins(managed, pins)
	if pinned[0].Version != "5.3.39" || pinned[1].Version != "5.3.39" || pinned[2].Version != "4.3.30" || pinned[4].Version != "9.0.83" {
		t.Fatalf("pinned %v", pinned)
	}

	// 3. the pinned artifacts the project manages explicitly: the two at the new version
	explicit := pinnedArtifacts(pinned, pins)
	if len(explicit) != 2 || explicit[0].Artifact != "spring-core" || explicit[1].Artifact != "spring-web" {
		t.Fatalf("explicit %v", explicit)
	}

	// 4. the roots after the pins: the spring group at 5.3.39, security, and extra at 9.9
	roots := selectRoots(pinned, rule)
	var keys []string
	for _, c := range roots {
		keys = append(keys, c.Key())
	}
	sort.Strings(keys)
	want := "org.example:extra:9.9 org.springframework.security:spring-security-core:5.7.11 org.springframework:spring-core:5.3.39 org.springframework:spring-legacy:4.3.30 org.springframework:spring-web:5.3.39"
	if strings.Join(keys, " ") != want {
		t.Fatalf("roots %v", keys)
	}

	// 5. the property round trip
	back := parsePins(pinsString(pins))
	if len(back) != 1 || back[0] != pins[0] {
		t.Fatalf("parsed %v", back)
	}
}

// The line's project: the pinned artifacts managed before the anchor's import, so
// they win, and every root a dependency.
func TestLinePOM(t *testing.T) {
	r := NewResolver()
	anchor := book.Anchor{Group: "org.springframework.boot", Artifact: "spring-boot-dependencies", Version: "2.7.18"}
	managed := []Component{{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.39"}}
	pins := []Pin{{Group: "org.springframework", From: "5.3.31", To: "5.3.39"}}
	roots := []Component{{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.39"}, {Group: "org.example", Artifact: "native", Version: "2.0", Classifier: "linux"}}
	p := r.linePOM(anchor, true, managed, pins, roots)
	pin := strings.Index(p, "<artifactId>spring-core</artifactId><version>5.3.39</version></dependency>")
	imp := strings.Index(p, "<scope>import</scope>")
	if pin < 0 || imp < 0 || pin > imp {
		t.Fatalf("the pin must come before the import:\n%s", p)
	}
	if !strings.Contains(p, "<dependencies>\n<dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>5.3.39</version></dependency>") {
		t.Fatalf("spring-core is not a dependency:\n%s", p)
	}
	if !strings.Contains(p, "<classifier>linux</classifier>") {
		t.Fatalf("the classifier is lost:\n%s", p)
	}
	if strings.Count(p, "<dependencyManagement>") != 1 {
		t.Fatalf("one dependencyManagement block:\n%s", p)
	}
}

// The build's tree as a graph: asm under two parents at the same version is one
// component, every parent has its edge to it, the roots are the project's direct
// dependencies, a test scoped child is left out.
func TestGraphFromTree(t *testing.T) {
	tree := `{"groupId":"osera.line","artifactId":"line","version":"1","type":"jar","scope":"","classifier":"","optional":"false","children":[
	 {"groupId":"org.example","artifactId":"a","version":"1.0","type":"jar","scope":"compile","classifier":"","optional":"false","children":[
	   {"groupId":"org.ow2.asm","artifactId":"asm","version":"9.6","type":"jar","scope":"compile","classifier":"","optional":"false","children":[]},
	   {"groupId":"org.example","artifactId":"tests","version":"1.0","type":"jar","scope":"test","classifier":"","optional":"false","children":[]}]},
	 {"groupId":"org.example","artifactId":"b","version":"2.0","type":"jar","scope":"runtime","classifier":"","optional":"false","children":[
	   {"groupId":"org.ow2.asm","artifactId":"asm","version":"9.6","type":"jar","scope":"compile","classifier":"","optional":"false","children":[]}]}]}`
	var root treeNode
	if err := json.Unmarshal([]byte(tree), &root); err != nil {
		t.Fatal(err)
	}
	g := &Graph{Dependencies: map[string][]string{}, Unresolved: map[string]string{}}
	graphFromTree(g, root)
	g.sortAll()
	var keys []string
	for _, c := range g.Components {
		keys = append(keys, c.Key())
	}
	if strings.Join(keys, " ") != "org.example:a:1.0 org.example:b:2.0 org.ow2.asm:asm:9.6" {
		t.Fatalf("components %v", keys)
	}
	if strings.Join(g.Roots, " ") != "org.example:a:1.0 org.example:b:2.0" {
		t.Fatalf("roots %v", g.Roots)
	}
	if len(g.Dependencies["org.example:a:1.0"]) != 1 || len(g.Dependencies["org.example:b:2.0"]) != 1 {
		t.Fatalf("edges %v", g.Dependencies)
	}
}

// When the single build fails, the probes take over and the graph says so.
func TestResolveFallsBackToProbes(t *testing.T) {
	// 1. a fake mvn: the line build fails, the batch run writes m0's tree from the fixture
	fixture, err := filepath.Abs(filepath.Join("testdata", "tree.json"))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "mvn")
	body := "#!/bin/sh\ncase \"$*\" in\n  *--fail-at-end*) cp \"" + fixture + "\" m0/tree.json; exit 0 ;;\nesac\necho '[ERROR] the line build is refused by this test'\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	// 2. the resolve on the fixture repository
	s := repository(t)
	r := NewResolver()
	r.HTTP = s.Client()
	r.RepositoryURLs = []string{s.URL + "/"}
	r.Maven = script
	r.ProbeTimeout = time.Minute
	anchor := book.Anchor{Group: "org.example", Artifact: "dev-bom", Version: "1.0"}
	rule := RuleFor(anchor, []string{"org.example:lib@1.0"})
	g, err := r.Resolve(context.Background(), "test", anchor, rule, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// 3. the method says why, and the probes gave the graph
	if !strings.HasPrefix(g.Method, "batched probes, the single build failed: ") || !strings.Contains(g.Method, "refused by this test") {
		t.Fatalf("method %q", g.Method)
	}
	if len(g.Roots) == 0 || len(g.Components) == 0 {
		t.Fatalf("empty graph %+v", g)
	}
	if g.Declared != "org.example:lib@1.0" {
		t.Fatalf("declared %q", g.Declared)
	}
}

// The file keeps the pins, the declared components and the method.
func TestCycloneDXKeepsTheBuildFacts(t *testing.T) {
	g := &Graph{LineID: "l", Anchor: book.Anchor{Group: "g", Artifact: "a", Version: "1"}, RootsRule: "groups:g", Declared: "g:c@2", Method: "one build",
		Pins: []Pin{{Group: "g", From: "1", To: "2"}}, Components: []Component{{Group: "g", Artifact: "c", Version: "2"}}, Roots: []string{"g:c:2"}, Dependencies: map[string][]string{}, Unresolved: map[string]string{}}
	path := filepath.Join(t.TempDir(), "maven.cdx.json")
	if err := Write(path, g, time.Now()); err != nil {
		t.Fatal(err)
	}
	back, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Declared != "g:c@2" || back.Method != "one build" || len(back.Pins) != 1 || back.Pins[0] != g.Pins[0] {
		t.Fatalf("read back %+v", back)
	}
}

// The real thing, only when asked: one build with two roots, commons-lang3 found under
// commons-text, one version of every library.
func TestBuildLineWithMaven(t *testing.T) {
	if os.Getenv("OSERA_MAVEN_TESTS") != "1" {
		t.Skip("set OSERA_MAVEN_TESTS=1 with mvn on PATH")
	}
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("mvn not on PATH")
	}
	r := NewResolver()
	anchor := book.Anchor{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8"}
	roots := []Component{{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8"}, {Group: "org.apache.commons", Artifact: "commons-text", Version: "1.10.0"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tree, why := r.buildLine(ctx, t.TempDir(), anchor, false, nil, nil, roots)
	if why != "" {
		t.Fatal(why)
	}
	g := &Graph{Dependencies: map[string][]string{}, Unresolved: map[string]string{}}
	graphFromTree(g, tree)
	g.sortAll()
	var keys []string
	for _, c := range g.Components {
		keys = append(keys, c.Key())
	}
	if strings.Join(keys, " ") != "com.google.code.gson:gson:2.8.8 org.apache.commons:commons-lang3:3.12.0 org.apache.commons:commons-text:1.10.0" {
		t.Fatalf("components %v", keys)
	}
	if len(g.Roots) != 2 {
		t.Fatalf("roots %v", g.Roots)
	}
}

// Only when asked, over the network: the Spring line's roots and pins from Boot 2.7.18 on Central.
func TestSpringRootsFromCentral(t *testing.T) {
	if os.Getenv("OSERA_MAVEN_TESTS") != "1" {
		t.Skip("set OSERA_MAVEN_TESTS=1")
	}
	r := NewResolver()
	anchor := book.Anchor{Group: "org.springframework.boot", Artifact: "spring-boot-dependencies", Version: "2.7.18"}
	rule := RuleFor(anchor, []string{"org.springframework:spring-core@5.3.39", "org.springframework.security:spring-security-core@5.7.11"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	m, err := r.readModel(ctx, anchor.Group, anchor.Artifact, anchor.Version)
	if err != nil {
		t.Fatal(err)
	}
	pins := pinsFor(m.Managed, rule)
	pinned := applyPins(m.Managed, pins)
	roots, err := r.roots(ctx, selectRoots(pinned, rule))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("managed %d, pins %s, roots %d, explicit pins %d", len(m.Managed), pinsString(pins), len(roots), len(pinnedArtifacts(pinned, pins)))
	if len(pins) == 0 {
		t.Fatal("spring-core 5.3.39 over Boot's 5.3.31 must pin the group")
	}
}
