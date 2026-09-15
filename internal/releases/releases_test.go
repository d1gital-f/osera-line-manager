// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package releases

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const evidenceYAML = `schema: osera-patch-evidence/0.1.0
producer: controlplane-dev
release: 2.14.2+osera-patch.001
baseline: v2.14.2+patch.baseline
fixes:
  - cve: CVE-2025-52999
    upstream: https://github.com/FasterXML/jackson-core/pull/943
    note: a regression test only
  - cve: CVE-2025-52999
tests:
  commit: 387b29be3747a51076fc3a49d40ea58c49c51ce6
  command: mvn -B clean package
  runtime: OpenJDK 21
  report: jackson-core-2.14.2+osera-patch.001-tests.zip
  result: pass
  totals: 121333 tests, 0 failures
bytecode_level: 52
`

// nexus is a fake release repository: a two page search and one evidence file.
func nexus(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/service/rest/v1/search", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("repository") != "osera-releases-maven-01" {
			http.Error(w, "wrong repository", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("format") != "maven2" {
			http.Error(w, "wrong format", http.StatusBadRequest)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "line-manager" || pass != "secret" {
			http.Error(w, "who are you", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continuationToken") == "" {
			w.Write([]byte(`{"items":[{"group":"com.fasterxml.jackson.core","name":"jackson-core","version":"2.14.2+osera-patch.001","assets":[{"path":"/com/fasterxml/jackson/core/jackson-core/2.14.2+osera-patch.001/jackson-core-2.14.2+osera-patch.001.jar"},{"path":"/com/fasterxml/jackson/core/jackson-core/2.14.2+osera-patch.001/jackson-core-2.14.2+osera-patch.001.pom"}]}],"continuationToken":"page-2"}`))
			return
		}
		w.Write([]byte(`{"items":[{"group":"org.finos.osera","name":"osera-bom-dev-1.0.x","version":"2026.10.07","assets":[{"path":"/org/finos/osera/osera-bom-dev-1.0.x/2026.10.07/osera-bom-dev-1.0.x-2026.10.07.pom"}]}],"continuationToken":null}`))
	})
	mux.HandleFunc("/repository/osera-releases-maven-01/com/fasterxml/jackson/core/jackson-core/2.14.2+osera-patch.001/jackson-core-2.14.2+osera-patch.001-osera-evidence.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(evidenceYAML))
	})
	return httptest.NewServer(mux)
}

// 1. A two page search lists both coordinates, the patched one split by REL-003.
func TestPromoted(t *testing.T) {
	srv := nexus(t)
	defer srv.Close()
	c := New(srv.URL, "line-manager", "secret")
	coords, err := c.Promoted(context.Background(), "osera-releases-maven-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(coords) != 2 {
		t.Fatalf("%d coordinates, want 2", len(coords))
	}
	j := coords[0]
	if j.String() != "com.fasterxml.jackson.core:jackson-core@2.14.2+osera-patch.001" {
		t.Fatalf("coordinate %q", j.String())
	}
	if !j.Patched() || j.Base != "2.14.2" || j.Patch != "001" {
		t.Fatalf("split %+v", j)
	}
	if len(j.Assets) != 2 {
		t.Fatalf("assets %v", j.Assets)
	}
	b := coords[1]
	if b.Patched() || b.Base != "" || b.Patch != "" {
		t.Fatalf("the BOM is not a patched coordinate: %+v", b)
	}
}

// 2. The evidence next to the jar is read and its CVEs listed once each.
func TestEvidence(t *testing.T) {
	srv := nexus(t)
	defer srv.Close()
	c := New(srv.URL, "line-manager", "secret")
	coord := NewCoordinate("com.fasterxml.jackson.core", "jackson-core", "2.14.2+osera-patch.001")
	ev, err := c.Evidence(context.Background(), "osera-releases-maven-01", coord)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Producer != "controlplane-dev" || ev.Release != "2.14.2+osera-patch.001" || ev.BytecodeLevel != 52 {
		t.Fatalf("evidence %+v", ev)
	}
	cves := ev.CVEs()
	if len(cves) != 1 || cves[0] != "CVE-2025-52999" {
		t.Fatalf("cves %v", cves)
	}
	if ev.Tests.Result != "pass" {
		t.Fatalf("tests %+v", ev.Tests)
	}
}

// 3. A coordinate without an evidence file is ErrNoEvidence.
func TestNoEvidence(t *testing.T) {
	srv := nexus(t)
	defer srv.Close()
	c := New(srv.URL, "line-manager", "secret")
	coord := NewCoordinate("org.finos.osera", "osera-bom-dev-1.0.x", "2026.10.07")
	_, err := c.Evidence(context.Background(), "osera-releases-maven-01", coord)
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("error %v, want ErrNoEvidence", err)
	}
}

// 4. The evidence path follows the jar's folder and name.
func TestEvidencePath(t *testing.T) {
	coord := NewCoordinate("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.83+osera-patch.001")
	want := "org/apache/tomcat/embed/tomcat-embed-core/9.0.83+osera-patch.001/tomcat-embed-core-9.0.83+osera-patch.001-osera-evidence.yaml"
	if EvidencePath(coord) != want {
		t.Fatalf("path %q", EvidencePath(coord))
	}
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

const componentJSON = `{"timestamp":"2026-10-07T10:00:00.000+0000","nodeId":"n1","initiator":"gate/1.2.3.4","repositoryName":"osera-releases-maven-01","action":"CREATED","component":{"id":"abc","format":"maven2","name":"tomcat-embed-core","group":"org.apache.tomcat.embed","version":"9.0.83+osera-patch.001"}}`

// 5. A signed maven2 event reaches the listener as an Event.
func TestWebhookGoodSignature(t *testing.T) {
	var got []Event
	h := Handler("s3cret", func(e Event) { got = append(got, e) })
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(componentJSON))
	req.Header.Set("X-Nexus-Webhook-Signature", sign("s3cret", []byte(componentJSON)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if len(got) != 1 {
		t.Fatalf("%d events, want 1", len(got))
	}
	e := got[0]
	if e.Repository != "osera-releases-maven-01" || e.Action != "CREATED" {
		t.Fatalf("event %+v", e)
	}
	if e.Coordinate.String() != "org.apache.tomcat.embed:tomcat-embed-core@9.0.83+osera-patch.001" || e.Coordinate.Base != "9.0.83" {
		t.Fatalf("coordinate %+v", e.Coordinate)
	}
}

// 6. A bad signature is refused and nothing reaches the listener.
func TestWebhookBadSignature(t *testing.T) {
	called := false
	h := Handler("s3cret", func(Event) { called = true })
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(componentJSON))
	req.Header.Set("X-Nexus-Webhook-Signature", sign("wrong", []byte(componentJSON)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if called {
		t.Fatal("the listener was called on a bad signature")
	}
}

// 7. A signed event for another format is acknowledged and dropped.
func TestWebhookNotMaven(t *testing.T) {
	called := false
	h := Handler("s3cret", func(Event) { called = true })
	body := strings.Replace(componentJSON, `"format":"maven2"`, `"format":"raw"`, 1)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	req.Header.Set("X-Nexus-Webhook-Signature", sign("s3cret", []byte(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if called {
		t.Fatal("the listener was called for a raw component")
	}
}

// 8. Put: the path under the repository, basic auth, a 409 treated as success, a 403 as an error.
func TestPut(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		seen = append(seen, r.Method+" "+r.URL.Path+" as "+user)
		switch {
		case strings.HasSuffix(r.URL.Path, "exists.pom"):
			w.WriteHeader(http.StatusConflict)
		case strings.HasSuffix(r.URL.Path, "refused.pom"):
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer server.Close()
	c := New(server.URL, "line-manager", "secret")
	c.HTTP = server.Client()
	ctx := context.Background()
	if err := c.Put(ctx, "osera-releases-maven-01", "/org/finos/osera/x/1/new.pom", []byte("<project/>"), "application/xml"); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "osera-releases-maven-01", "org/finos/osera/x/1/exists.pom", []byte("<project/>"), "application/xml"); err != nil {
		t.Fatalf("a 409 must be success: %v", err)
	}
	if err := c.Put(ctx, "osera-releases-maven-01", "org/finos/osera/x/1/refused.pom", []byte("<project/>"), "application/xml"); err == nil {
		t.Fatal("a 403 went unnoticed")
	}
	if seen[0] != "PUT /repository/osera-releases-maven-01/org/finos/osera/x/1/new.pom as line-manager" {
		t.Fatalf("first call %s", seen[0])
	}
}

// The two ratified forms of a patched version split the way the fitness library splits them.
func TestNewCoordinateBothForms(t *testing.T) {
	cases := []struct{ version, base, patch string }{
		{"2.14.2+osera-patch.001", "2.14.2", "001"},
		{"5.3.39.1-osera-00001", "5.3.39", "00001"},
		{"5.6.15.Final-osera-00001", "5.6.15.Final", "00001"},
		{"9.0.83", "", ""},
		{"1.0-osera-x", "", ""},
	}
	for _, c := range cases {
		got := NewCoordinate("g", "a", c.version)
		if got.Base != c.base || got.Patch != c.patch {
			t.Fatalf("%s: base %q patch %q, want %q %q", c.version, got.Base, got.Patch, c.base, c.patch)
		}
	}
}

// The Java form is read the way the gate reads it: the .N the patch added is dropped
// whatever the upstream's number of components.
func TestNewCoordinateCARE(t *testing.T) {
	cases := map[string][2]string{
		"5.3.39.1-osera-00001":     {"5.3.39", "00001"},
		"1.33.1-osera-00001":       {"1.33", "00001"},
		"3.10.6.Final-osera-00001": {"3.10.6.Final", "00001"},
		"2.14.2+osera-patch.001":   {"2.14.2", "001"},
		"1.33":                     {"", ""},
	}
	for version, want := range cases {
		c := NewCoordinate("g", "a", version)
		if c.Base != want[0] || c.Patch != want[1] {
			t.Fatalf("%s: base %q patch %q", version, c.Base, c.Patch)
		}
	}
}
