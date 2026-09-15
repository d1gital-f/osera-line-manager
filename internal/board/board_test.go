// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package board

import (
	"context"
	"encoding/json"
	"github.com/d1gital-f/osera-line-manager/internal/status"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A board of two pages: three CVE issues, one closed with the label, one card
// that is a draft (not an issue), one issue whose title carries no CVE.
const pageOne = `{"data":{"organization":{"projectV2":{"id":"proj-1","field":{"id":"field-status","options":[{"id":"opt-todo","name":"Not claimed"},{"id":"opt-prog","name":"In Progress"},{"id":"opt-done","name":"Patched"}]},"items":{
  "pageInfo":{"hasNextPage":true,"endCursor":"c1"},
  "nodes":[
    {"id":"item-1","fieldValueByName":{"name":"Not claimed"},"content":{"__typename":"Issue","number":1,"title":"P0 CVE-2025-24813 in tomcat-embed-core 9.0.83","state":"OPEN","url":"u1","repository":{"name":"backlog"},"labels":{"nodes":[{"name":"cve"},{"name":"P0 / Act"}]}}},
    {"content":{"__typename":"DraftIssue","number":0,"title":"a note","state":"","url":"","repository":{"name":""},"labels":{"nodes":[]}}},
    {"content":{"__typename":"Issue","number":2,"title":"line spring-boot-2.7.x is supported","state":"OPEN","url":"u2","repository":{"name":"backlog"},"labels":{"nodes":[]}}}
  ]}}}}}`

const pageTwo = `{"data":{"organization":{"projectV2":{"items":{
  "pageInfo":{"hasNextPage":false,"endCursor":""},
  "nodes":[
    {"id":"item-3","fieldValueByName":{"name":"In Progress"},"content":{"__typename":"Issue","number":3,"title":"P1 CVE-2024-38816 in spring-webmvc 5.3.39","state":"OPEN","url":"u3","repository":{"name":"patch-spring-framework"},"labels":{"nodes":[{"name":"cve"}]}}},
    {"content":{"__typename":"Issue","number":4,"title":"P1 CVE-2016-1000027 in spring-web 5.3.39","state":"CLOSED","url":"u4","repository":{"name":"patch-spring-framework"},"labels":{"nodes":[{"name":"cve"},{"name":"not remediable"}]}}},
    {"content":{"__typename":"Issue","number":5,"title":"P1 CVE-2024-38816 in spring-webmvc 5.3.39","state":"OPEN","url":"u5","repository":{"name":"backlog"},"labels":{"nodes":[]}}}
  ]}}}}}`

func server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. the request is a GraphQL query with our variables
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Variables["owner"] != "dev-finos-osera-forks" || req.Variables["number"] != float64(1) {
			t.Fatalf("variables %v", req.Variables)
		}

		// 2. the second page follows the cursor of the first
		w.Header().Set("Content-Type", "application/json")
		if req.Variables["after"] == "c1" {
			w.Write([]byte(pageTwo))
			return
		}
		w.Write([]byte(pageOne))
	}))
}

// 1. Two pages, one query each: four cards, the draft and the title without a CVE skipped.
// The token comes from the provider on every request.
func TestTokenProvider(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"data":{"organization":{"projectV2":{"items":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[]}}}}}`))
	}))
	defer srv.Close()
	c := New("dev-finos-osera-forks", 1, StaticToken("fresh"))
	c.URL = srv.URL
	if _, err := c.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer fresh" {
		t.Fatalf("authorization %q", seen)
	}
}

func TestReadTwoPages(t *testing.T) {
	s := server(t)
	defer s.Close()
	c := New("dev-finos-osera-forks", 1, StaticToken("t0k"))
	c.URL = s.URL
	cards, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 4 {
		t.Fatalf("cards %d, want 4: %+v", len(cards), cards)
	}
	if cards[0].CVE != "CVE-2025-24813" || cards[0].Repository != "backlog" || cards[0].State != "OPEN" {
		t.Fatalf("first card %+v", cards[0])
	}
	if cards[2].CVE != "CVE-2016-1000027" || cards[2].State != "CLOSED" || len(cards[2].Labels) != 2 {
		t.Fatalf("third card %+v", cards[2])
	}
}

// 2. One issue per CVE: the patch repository wins over the backlog, the label is read.
func TestIssues(t *testing.T) {
	s := server(t)
	defer s.Close()
	c := New("dev-finos-osera-forks", 1, StaticToken("t0k"))
	c.URL = s.URL
	cards, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	issues := Issues(cards, "backlog")
	if len(issues) != 3 {
		t.Fatalf("issues %d, want 3: %+v", len(issues), issues)
	}
	byCVE := map[string]int{}
	for i, is := range issues {
		byCVE[is.CVE] = i
	}
	taken := issues[byCVE["CVE-2024-38816"]]
	if taken.Repository != "patch-spring-framework" {
		t.Fatalf("CVE-2024-38816 should be in the patch repository, got %+v", taken)
	}
	declared := issues[byCVE["CVE-2016-1000027"]]
	if !declared.NotRemediable || declared.State != "CLOSED" {
		t.Fatalf("CVE-2016-1000027 should carry the label, got %+v", declared)
	}
	open := issues[byCVE["CVE-2025-24813"]]
	if open.NotRemediable || open.Repository != "backlog" {
		t.Fatalf("CVE-2025-24813 should be open in the backlog, got %+v", open)
	}
}

// 3. A GraphQL error in a 200 answer is an error.
func TestGraphQLError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":null,"errors":[{"message":"Could not resolve to a ProjectV2 with the number 9."}]}`))
	}))
	defer s.Close()
	c := New("dev-finos-osera-forks", 9, StaticToken("t0k"))
	c.URL = s.URL
	if _, err := c.Read(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// 3. The first page teaches the client the board's id, its Status field and its lanes;
// every card carries its item id and lane; LaneOption ignores letter case.
func TestReadLearnsTheLanes(t *testing.T) {
	srv := server(t)
	defer srv.Close()
	c := New("dev-finos-osera-forks", 1, StaticToken("t"))
	c.URL = srv.URL
	cards, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.ProjectID != "proj-1" || c.StatusFieldID != "field-status" || len(c.Lanes) != 3 {
		t.Fatalf("project %q field %q lanes %v", c.ProjectID, c.StatusFieldID, c.Lanes)
	}
	if c.LaneOption("in progress") != "opt-prog" || c.LaneOption("Done") != "" {
		t.Fatalf("lane option lookup: %v", c.Lanes)
	}
	if cards[0].ItemID != "item-1" || cards[0].Lane != "Not claimed" {
		t.Fatalf("card 1 %+v", cards[0])
	}
	is := Issues(cards, "backlog")
	for _, i := range is {
		if i.Number == 3 && (i.ItemID != "item-3" || i.Lane != "In Progress") {
			t.Fatalf("issue 3 lost its card: %+v", i)
		}
	}
}

// 4. A closed duplicate in the backlog does not shadow the open issue for the same CVE.
func TestIssuesPreferTheOpenCard(t *testing.T) {
	cards := []Card{
		{CVE: "CVE-1", Repository: "backlog", Number: 166, State: "CLOSED"},
		{CVE: "CVE-1", Repository: "backlog", Number: 172, State: "OPEN"},
		{CVE: "CVE-2", Repository: "patch-a", Number: 1, State: "CLOSED"},
		{CVE: "CVE-2", Repository: "backlog", Number: 9, State: "OPEN"},
	}
	is := Issues(cards, "backlog")
	if is[0].Number != 172 || is[1].Number != 1 {
		t.Fatalf("issues %+v", is)
	}
}

// 5. An issue is one per CVE and library version, read from its title; an older title
// without a version stands for the CVE alone.
func TestIssuesPerLibraryVersion(t *testing.T) {
	cards := []Card{
		{CVE: "CVE-1", Title: "P1 CVE-1 in jackson-core 2.14.2", Repository: "patch-jackson-core", Number: 3, State: "OPEN"},
		{CVE: "CVE-1", Title: "P1 CVE-1 in jackson-core 2.13.5", Repository: "backlog", Number: 9, State: "OPEN"},
		{CVE: "CVE-2", Title: "P0 CVE-2 in snakeyaml", Repository: "backlog", Number: 4, State: "OPEN"},
	}
	for i := range cards {
		if m := libraryInTitle.FindStringSubmatch(cards[i].Title); m != nil {
			cards[i].Artifact, cards[i].Version = m[1], m[2]
		}
	}
	is := Issues(cards, "backlog")
	if len(is) != 3 || is[0].Version != "2.14.2" || is[1].Version != "2.13.5" || is[2].Artifact != "" {
		t.Fatalf("issues %+v", is)
	}
	idx := status.IndexCards(is)
	if c, ok := idx.For("CVE-1", "com.fasterxml.jackson.core:jackson-core", "2.13.5"); !ok || c.Number != 9 {
		t.Fatalf("the 2.13.5 entry must find its own issue: %+v %v", c, ok)
	}
	if c, ok := idx.For("CVE-1", "com.fasterxml.jackson.core:jackson-core", "2.12.0"); ok {
		t.Fatalf("no issue for an unlisted version, got %+v", c)
	}
	if c, ok := idx.For("CVE-2", "org.yaml:snakeyaml", "1.33"); !ok || c.Number != 4 {
		t.Fatalf("an older issue without a version stands for the CVE: %+v %v", c, ok)
	}
}
