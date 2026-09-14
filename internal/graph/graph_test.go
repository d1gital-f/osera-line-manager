// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// A small repository: a parent with properties, a BOM child, a jar, a pom packaged artifact.
func repository(t *testing.T) *httptest.Server {
	t.Helper()
	files := map[string]string{
		"/org/example/parent/1.0/parent-1.0.pom": `<project><modelVersion>4.0.0</modelVersion>
<groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version><packaging>pom</packaging>
<properties><gson.version>2.8.8</gson.version><lib.version>${project.version}</lib.version></properties>
<dependencyManagement><dependencies>
<dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>${gson.version}</version></dependency>
<dependency><groupId>org.example</groupId><artifactId>other-bom</artifactId><version>9</version><type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement></project>`,
		"/org/example/dev-bom/1.0/dev-bom-1.0.pom": `<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
<artifactId>dev-bom</artifactId><packaging>pom</packaging>
<properties><gson.version>2.8.9</gson.version></properties>
<dependencyManagement><dependencies>
<dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>${lib.version}</version></dependency>
<dependency><groupId>org.example</groupId><artifactId>aggregator</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.example</groupId><artifactId>unset</artifactId><version>${nowhere}</version></dependency>
</dependencies></dependencyManagement>
<dependencies>
<dependency><groupId>org.example</groupId><artifactId>lib</artifactId></dependency>
<dependency><groupId>org.example</groupId><artifactId>tests</artifactId><version>1</version><scope>test</scope></dependency>
<dependency><groupId>org.example</groupId><artifactId>opt</artifactId><version>1</version><optional>true</optional></dependency>
</dependencies></project>`,
		"/org/example/lib/1.0/lib-1.0.pom":                `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0</version></project>`,
		"/org/example/aggregator/1.0/aggregator-1.0.pom":  `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>aggregator</artifactId><version>1.0</version><packaging>pom</packaging></project>`,
		"/com/google/code/gson/gson/2.8.9/gson-2.8.9.pom": `<project><modelVersion>4.0.0</modelVersion><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>2.8.9</version><packaging>jar</packaging></project>`,
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, found := files[r.URL.Path]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

//  1. A POM with a parent and properties: the child's property wins, imports are left out,
//     an unresolvable version is dropped, declared test and optional dependencies are dropped.
func TestReadModel(t *testing.T) {
	s := repository(t)
	r := NewResolver()
	r.HTTP = s.Client()
	r.RepositoryURLs = []string{s.URL + "/"}
	m, err := r.readModel(context.Background(), "org.example", "dev-bom", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if m.Group != "org.example" || m.Version != "1.0" || m.Packaging != "pom" {
		t.Fatalf("model %+v", m)
	}
	managed := map[string]string{}
	for _, c := range m.Managed {
		managed[c.Group+":"+c.Artifact] = c.Version
	}
	if managed["com.google.code.gson:gson"] != "2.8.9" {
		t.Fatalf("gson version %q, want the child's 2.8.9", managed["com.google.code.gson:gson"])
	}
	if managed["org.example:lib"] != "1.0" {
		t.Fatalf("lib version %q, want 1.0 through project.version", managed["org.example:lib"])
	}
	if _, found := managed["org.example:other-bom"]; found {
		t.Fatalf("an import is not a managed artifact")
	}
	if _, found := managed["org.example:unset"]; found {
		t.Fatalf("an unresolvable version is dropped")
	}
	if len(m.Declared) != 1 || m.Declared[0].Artifact != "lib" || m.Declared[0].Version != "1.0" {
		t.Fatalf("declared %+v, want lib 1.0 only", m.Declared)
	}
}

// 2. The roots of a BOM: managed artifacts that are not pom packaged and exist in the repository.
func TestRoots(t *testing.T) {
	s := repository(t)
	r := NewResolver()
	r.HTTP = s.Client()
	r.RepositoryURLs = []string{s.URL + "/"}
	m, err := r.readModel(context.Background(), "org.example", "dev-bom", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	roots, err := r.roots(context.Background(), m.Managed)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range roots {
		names = append(names, c.Artifact)
	}
	if len(roots) != 2 || names[0] != "gson" || names[1] != "lib" {
		t.Fatalf("roots %v, want gson and lib (the aggregator is a pom)", names)
	}
}

// 3. The tree JSON of a probe: direct children in compile and runtime scope, not optional, classifier kept.
func TestReadTree(t *testing.T) {
	children, err := readTree("testdata/tree.json")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, c := range children {
		keys = append(keys, c.Key())
	}
	want := []string{"org.example:runtime-dep:1.0", "org.example:native:2.0:linux-x86_64"}
	if len(keys) != len(want) {
		t.Fatalf("children %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("children %v, want %v", keys, want)
		}
	}
	if children[1].PURL() != "pkg:maven/org.example/native@2.0?classifier=linux-x86_64" {
		t.Fatalf("purl %s", children[1].PURL())
	}
}

// 4. The probe POM: the anchor imported when it is a BOM, the extra repository listed.
func TestProbePOM(t *testing.T) {
	r := NewResolver()
	r.RepositoryURLs = []string{Central, "https://repo.dev.finos.org/repository/osera-releases-maven/"}
	anchor := book.Anchor{Group: "org.finos.osera.dev", Artifact: "dev-bom", Version: "1.0.0"}
	p := r.probePOM(anchor, true, Component{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"})
	for _, want := range []string{"<scope>import</scope>", "<artifactId>dev-bom</artifactId>", "<artifactId>snakeyaml</artifactId>", "repo.dev.finos.org"} {
		if !contains(p, want) {
			t.Fatalf("probe POM lacks %q:\n%s", want, p)
		}
	}
	plain := r.probePOM(anchor, false, Component{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"})
	if contains(plain, "<scope>import</scope>") {
		t.Fatalf("a jar anchor is not imported")
	}
}

// 5. Write, read and check: the round trip keeps the line, the anchor, every component and every edge.
func TestCycloneDXRoundTrip(t *testing.T) {
	anchor := book.Anchor{Group: "org.finos.osera.dev", Artifact: "dev-bom", Version: "1.0.0"}
	g := &Graph{
		LineID: "dev-1.0.x",
		Anchor: anchor,
		Components: []Component{
			{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8", Type: "jar"},
			{Group: "org.example", Artifact: "native", Version: "2.0", Classifier: "linux-x86_64", Type: "jar"},
			{Group: "org.example", Artifact: "deep", Version: "3.0", Type: "jar"},
		},
		Roots:        []string{"com.google.code.gson:gson:2.8.8"},
		Dependencies: map[string][]string{"com.google.code.gson:gson:2.8.8": {"org.example:native:2.0:linux-x86_64"}, "org.example:native:2.0:linux-x86_64": {"org.example:deep:3.0"}, "org.example:deep:3.0": {}},
		Unresolved:   map[string]string{"org.example:deep:3.0": "read from the POM, Maven failed: no model"},
	}
	path := filepath.Join(t.TempDir(), "maven.cdx.json")
	err := Write(path, g, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{`"bomFormat": "CycloneDX"`, `"specVersion": "1.6"`, `"osera:line"`, `"dev-1.0.x"`, `"pkg:maven/org.finos.osera.dev/dev-bom@1.0.0?type=pom"`} {
		if !contains(string(raw), want) {
			t.Fatalf("file lacks %s", want)
		}
	}
	back, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(back, "dev-1.0.x", anchor); err != nil {
		t.Fatal(err)
	}
	if err := Check(back, "spring-boot-2.7.x", anchor); err == nil {
		t.Fatalf("a wrong line must fail the check")
	}
	if len(back.Components) != 3 || len(back.Roots) != 1 || back.Roots[0] != "com.google.code.gson:gson:2.8.8" {
		t.Fatalf("read back %+v", back)
	}
	if len(back.Dependencies["com.google.code.gson:gson:2.8.8"]) != 1 || back.Dependencies["com.google.code.gson:gson:2.8.8"][0] != "org.example:native:2.0:linux-x86_64" {
		t.Fatalf("edges %v", back.Dependencies)
	}
	if back.Unresolved["org.example:deep:3.0"] == "" {
		t.Fatalf("the unresolved mark was lost")
	}
	native, found := back.component("org.example:native:2.0:linux-x86_64")
	if !found || native.Classifier != "linux-x86_64" {
		t.Fatalf("classifier lost: %+v", native)
	}
}

// 6. The real thing, only when asked: gson 2.8.8 as a one root anchor against Central.
func TestResolveWithMaven(t *testing.T) {
	if os.Getenv("OSERA_MAVEN_TESTS") != "1" {
		t.Skip("set OSERA_MAVEN_TESTS=1 with mvn on PATH")
	}
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("mvn not on PATH")
	}
	r := NewResolver()
	anchor := book.Anchor{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	g, err := r.Resolve(ctx, "test-gson", anchor, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Roots) != 1 || g.Roots[0] != "com.google.code.gson:gson:2.8.8" {
		t.Fatalf("roots %v", g.Roots)
	}
	if len(g.Components) != 1 {
		t.Fatalf("gson 2.8.8 has no runtime dependencies, got %v", g.Components)
	}
	if len(g.Unresolved) != 0 {
		t.Fatalf("unresolved %v", g.Unresolved)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
