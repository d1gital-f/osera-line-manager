// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package bom

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d1gital-f/osera-line-manager/internal/book"
	"github.com/d1gital-f/osera-line-manager/internal/releases"
	"github.com/d1gital-f/osera-line-manager/internal/status"
)

var line = book.Line{ID: "spring-boot-2.7.x"}

// 1. Three fixed entries, two on the same set: one dependency per library, sorted, the POM as expected.
func TestBuildAndWrite(t *testing.T) {
	fixed := []status.FixedEntry{
		{CVE: "CVE-2025-24813", Coordinate: "org.apache.tomcat.embed:tomcat-embed-core@9.0.83+osera-patch.001"},
		{CVE: "CVE-2024-38816", Coordinate: "org.springframework:spring-web@5.3.39+osera-patch.001"},
		{CVE: "CVE-2024-38816", Coordinate: "org.springframework:spring-webmvc@5.3.39+osera-patch.001"},
		{CVE: "CVE-2024-38819", Coordinate: "org.springframework:spring-web@5.3.39+osera-patch.001"},
		{CVE: "CVE-2024-38819", Coordinate: "org.springframework:spring-webmvc@5.3.39+osera-patch.001"},
	}
	b, err := Build(line, fixed, "2026.10.07")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Dependencies) != 3 {
		t.Fatalf("%d dependencies: %+v", len(b.Dependencies), b.Dependencies)
	}
	if b.Dependencies[0].Artifact != "tomcat-embed-core" || b.Dependencies[1].Artifact != "spring-web" || b.Dependencies[2].Artifact != "spring-webmvc" {
		t.Fatalf("order %+v", b.Dependencies)
	}
	if b.Coordinate() != "org.finos.osera:osera-bom-spring-boot-2.7.x@2026.10.07" {
		t.Fatalf("coordinate %s", b.Coordinate())
	}
	if b.Path() != "org/finos/osera/osera-bom-spring-boot-2.7.x/2026.10.07/osera-bom-spring-boot-2.7.x-2026.10.07.pom" {
		t.Fatalf("path %s", b.Path())
	}
	raw, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		"<!--",
		"<groupId>org.finos.osera</groupId>",
		"<artifactId>osera-bom-spring-boot-2.7.x</artifactId>",
		"<version>2026.10.07</version>",
		"<packaging>pom</packaging>",
		"<dependencyManagement>",
		"<version>9.0.83+osera-patch.001</version>",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("POM lacks %s:\n%s", want, text)
		}
	}
	if strings.Count(text, "<dependency>") != 3 {
		t.Fatalf("%d dependency blocks", strings.Count(text, "<dependency>"))
	}
}

// 2. The same library at two patched versions is an error, not a choice.
func TestBuildConflict(t *testing.T) {
	fixed := []status.FixedEntry{
		{CVE: "CVE-1", Coordinate: "org.example:lib@1.0+osera-patch.001"},
		{CVE: "CVE-2", Coordinate: "org.example:lib@1.0+osera-patch.002"},
	}
	_, err := Build(line, fixed, "2026.10.07")
	if err == nil || !strings.Contains(err.Error(), "one version per library") {
		t.Fatalf("conflict not reported: %v", err)
	}
	_, err = Build(line, []status.FixedEntry{{CVE: "CVE-3", Coordinate: "broken"}}, "2026.10.07")
	if err == nil {
		t.Fatal("a broken coordinate was accepted")
	}
}

// 3. The version: the date, then .2, .3 when taken.
func TestVersion(t *testing.T) {
	now := time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)
	if v := Version(now, nil); v != "2026.10.07" {
		t.Fatalf("first %s", v)
	}
	if v := Version(now, []string{"2026.10.07"}); v != "2026.10.07.2" {
		t.Fatalf("second %s", v)
	}
	if v := Version(now, []string{"2026.10.07", "2026.10.07.2"}); v != "2026.10.07.3" {
		t.Fatalf("third %s", v)
	}
	if v := Version(now, []string{"2026.10.06"}); v != "2026.10.07" {
		t.Fatalf("another day %s", v)
	}
}

// 4. The upload: three PUTs with basic auth, the checksum of the bytes sent, a 409 is fine.
func TestUpload(t *testing.T) {
	var paths []string
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "line-manager" || pass != "secret" {
			t.Errorf("auth %q %q %v", user, pass, ok)
		}
		if r.Method != http.MethodPut {
			t.Errorf("method %s", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		paths = append(paths, r.URL.Path)
		bodies = append(bodies, raw)
		if strings.HasSuffix(r.URL.Path, ".md5") {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client := releases.New(server.URL, "line-manager", "secret")
	client.HTTP = server.Client()
	b, err := Build(line, []status.FixedEntry{{CVE: "CVE-1", Coordinate: "org.example:lib@1.0+osera-patch.001"}}, "2026.10.07")
	if err != nil {
		t.Fatal(err)
	}
	if err := Upload(context.Background(), client, "osera-releases-maven-01", b); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("%d PUTs: %v", len(paths), paths)
	}
	base := "/repository/osera-releases-maven-01/org/finos/osera/osera-bom-spring-boot-2.7.x/2026.10.07/osera-bom-spring-boot-2.7.x-2026.10.07.pom"
	if paths[0] != base || paths[1] != base+".sha1" || paths[2] != base+".md5" {
		t.Fatalf("paths %v", paths)
	}
	sum := sha1.Sum(bodies[0])
	if string(bodies[1]) != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha1 %s does not match the POM sent", bodies[1])
	}
}

// 5. An upload refused is an error.
func TestUploadRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client := releases.New(server.URL, "line-manager", "wrong")
	client.HTTP = server.Client()
	b, _ := Build(line, nil, "2026.10.07")
	if err := Upload(context.Background(), client, "osera-releases-maven-01", b); err == nil {
		t.Fatal("a 403 went unnoticed")
	}
}

// The version index: every version sorted, the latest twice as Maven writes it, read back.
func TestIndex(t *testing.T) {
	raw := Index("dev-1.0.x", []string{"2026.09.15.2", "2026.09.15"}, time.Date(2026, 9, 15, 13, 9, 33, 0, time.UTC))
	want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>org.finos.osera</groupId>\n  <artifactId>osera-bom-dev-1.0.x</artifactId>\n  <versioning>\n    <latest>2026.09.15.2</latest>\n    <release>2026.09.15.2</release>\n    <versions>\n      <version>2026.09.15</version>\n      <version>2026.09.15.2</version>\n    </versions>\n    <lastUpdated>20260915130933</lastUpdated>\n  </versioning>\n</metadata>\n"
	if string(raw) != want {
		t.Fatalf("index:\n%s", raw)
	}
	if v := IndexVersions(raw); len(v) != 2 || v[0] != "2026.09.15" || v[1] != "2026.09.15.2" {
		t.Fatalf("read back %v", v)
	}
	if IndexPath("dev-1.0.x") != "org/finos/osera/osera-bom-dev-1.0.x/maven-metadata.xml" {
		t.Fatal(IndexPath("dev-1.0.x"))
	}
}
