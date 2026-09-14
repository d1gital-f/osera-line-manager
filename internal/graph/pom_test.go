// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A repository with credentials: the POM read carries basic auth, Central does not.
func TestFetchPOMWithCredentials(t *testing.T) {
	// 1. a repository that wants the line manager's account
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seen = req.Header.Get("Authorization")
		if seen == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version><packaging>pom</packaging></project>`))
	}))
	defer srv.Close()
	r := NewResolver()
	r.RepositoryURLs = []string{srv.URL + "/repository/osera-releases-maven-01/"}
	r.Servers = []Server{{URL: srv.URL + "/repository/osera-releases-maven-01/", User: "line-manager", Password: "secret"}}

	// 2. the read succeeds with the account
	raw, err := r.fetchPOM(context.Background(), "g", "a", "1")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("empty POM")
	}
	if !strings.HasPrefix(seen, "Basic ") {
		t.Fatalf("no basic auth sent: %q", seen)
	}

	// 3. the settings file names the same server under the POM's repository id
	settings := r.settingsXML()
	if !strings.Contains(settings, "<id>osera-0</id>") || !strings.Contains(settings, "<username>line-manager</username>") {
		t.Fatalf("settings: %s", settings)
	}
	if !r.needsSettings() {
		t.Fatal("needsSettings false with a server")
	}
}
