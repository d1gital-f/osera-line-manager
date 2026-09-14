// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// The throwaway project of a batch: the parent lists one module per component, every
// module POM has its own artifact id, the anchor imported when it is a BOM.
func TestWriteBatch(t *testing.T) {
	r := NewResolver()
	anchor := book.Anchor{Group: "org.finos.osera.dev", Artifact: "dev-bom", Version: "1.0.0"}
	chunk := []Component{
		{Group: "org.yaml", Artifact: "snakeyaml", Version: "1.33"},
		{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8"},
	}
	dir := t.TempDir()
	if err := r.writeBatch(dir, anchor, true, chunk); err != nil {
		t.Fatal(err)
	}

	// 1. the parent
	parent, _ := os.ReadFile(filepath.Join(dir, "pom.xml"))
	for _, want := range []string{"<packaging>pom</packaging>", "<module>m0</module>", "<module>m1</module>"} {
		if !contains(string(parent), want) {
			t.Fatalf("parent POM lacks %q:\n%s", want, parent)
		}
	}

	// 2. the modules, distinct in the reactor
	m0, _ := os.ReadFile(filepath.Join(dir, "m0", "pom.xml"))
	m1, _ := os.ReadFile(filepath.Join(dir, "m1", "pom.xml"))
	if !contains(string(m0), "<artifactId>probe-m0</artifactId>") || !contains(string(m0), "<artifactId>snakeyaml</artifactId>") || !contains(string(m0), "<scope>import</scope>") {
		t.Fatalf("module 0:\n%s", m0)
	}
	if !contains(string(m1), "<artifactId>probe-m1</artifactId>") || !contains(string(m1), "<artifactId>gson</artifactId>") {
		t.Fatalf("module 1:\n%s", m1)
	}
}

// A batch where one module's tree is missing: that component falls back to the single
// probe, which here cannot run Maven either and reads the POM instead, marked; the
// other component's children come from the batch run.
func TestProbeBatchFallback(t *testing.T) {
	// 1. a fake mvn: on the reactor run it writes m0's tree from the fixture and nothing for m1;
	//    on a single probe it writes nothing at all
	fixture, err := filepath.Abs(filepath.Join("testdata", "tree.json"))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "mvn")
	body := "#!/bin/sh\ncase \"$*\" in\n  *--fail-at-end*) cp \"" + fixture + "\" m0/tree.json ;;\nesac\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	// 2. the resolver on the fixture repository, so the fallback finds lib's POM
	s := repository(t)
	r := NewResolver()
	r.HTTP = s.Client()
	r.RepositoryURLs = []string{s.URL + "/"}
	r.Maven = script
	r.ProbeTimeout = time.Minute
	anchor := book.Anchor{Group: "org.example", Artifact: "dev-bom", Version: "1.0"}
	chunk := []Component{
		{Group: "org.example", Artifact: "first", Version: "1.0"},
		{Group: "org.example", Artifact: "lib", Version: "1.0"},
	}
	results, err := r.probeAll(context.Background(), t.TempDir(), anchor, true, chunk)
	if err != nil {
		t.Fatal(err)
	}

	// 3. m0 from the batch tree, m1 from the fallback
	if results[0].err != "" || len(results[0].children) == 0 {
		t.Fatalf("first: %+v", results[0])
	}
	if results[1].err == "" || !contains(results[1].err, "read from the POM") {
		t.Fatalf("lib should have fallen back to its POM: %+v", results[1])
	}
}

// The real thing, only when asked: three roots resolved in one reactor run.
func TestProbeBatchWithMaven(t *testing.T) {
	if os.Getenv("OSERA_MAVEN_TESTS") != "1" {
		t.Skip("set OSERA_MAVEN_TESTS=1 with mvn on PATH")
	}
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("mvn not on PATH")
	}
	r := NewResolver()
	anchor := book.Anchor{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8"}
	chunk := []Component{
		{Group: "com.google.code.gson", Artifact: "gson", Version: "2.8.8"},
		{Group: "commons-io", Artifact: "commons-io", Version: "2.11.0"},
		{Group: "org.apache.commons", Artifact: "commons-text", Version: "1.10.0"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	results, err := r.probeAll(ctx, t.TempDir(), anchor, false, chunk)
	if err != nil {
		t.Fatal(err)
	}
	for i, res := range results {
		if res.err != "" {
			t.Fatalf("module %d: %s", i, res.err)
		}
	}
	if len(results[0].children) != 0 || len(results[1].children) != 0 {
		t.Fatalf("gson and commons-io have no runtime children: %+v %+v", results[0].children, results[1].children)
	}
	if len(results[2].children) != 1 || results[2].children[0].Artifact != "commons-lang3" {
		t.Fatalf("commons-text should pull commons-lang3: %+v", results[2].children)
	}
}
