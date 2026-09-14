// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"strings"
	"testing"
)

// The file as the dev backlog publishes it (rules/prioritisation.yaml, 14 Sept 2026).
const liveRules = `version: 0.1.0
source: https://github.com/finos-osera/risk-navigator/issues/7
bands:
  critical: 9.0
  high: 7.0
  medium: 4.0
signals:
  epss_percentile: 0.90
  kev: true
  member_exploit_evidence: true
  on_runtime_path_and_listed: true
  fixed_by_upgrade: true
include:
  - rule: critical
    when: band == critical
  - rule: high
    when: band == high
  - rule: kev
    when: kev
  - rule: medium-signal
    when: score >= 6.0 and score < 7.0 and any signal
priority:
  - P0 / Act:         kev or (band == critical and (epss signal or member exploit evidence))
  - P1 / Attend:      score >= 7.0
  - P2 / Investigate: score >= 6.0 and score < 7.0 and any signal
  - P3 / Track:       score >= 6.0 and score < 7.0
  - P4 / Exclude:     otherwise
curated_list:
  groups: [org.apache.logging.log4j, ch.qos.logback, org.slf4j, io.netty, io.projectreactor.netty, org.yaml]
  prefixes: [org.springframework, com.fasterxml.jackson, org.apache.tomcat, org.eclipse.jetty, org.hibernate]
`

func load(t *testing.T) *Rules {
	r, err := Parse([]byte(liveRules))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func score(s float64) *float64 {
	return &s
}

// 1. The outcomes mirror prioritisation_rules.evaluate, case by case.
func TestEvaluate(t *testing.T) {
	r := load(t)
	cases := []struct {
		name string
		f    Facts
		want Outcome
	}{
		{
			name: "critical with epss: P0, in by critical",
			f:    Facts{Score: score(9.8), CVSSSource: "nvd", EPSSPercentile: score(0.99), MemberLevel: MemberNone},
			want: Outcome{Band: Critical, Applicable: true, Rule: "critical", Priority: P0, Inputs: []string{"nvd", "epss"}, Signals: []string{"epss"}},
		},
		{
			name: "critical without epss: P1, in by critical",
			f:    Facts{Score: score(9.1), CVSSSource: "nvd", EPSSPercentile: score(0.2), MemberLevel: MemberNone},
			want: Outcome{Band: Critical, Applicable: true, Rule: "critical", Priority: P1, Inputs: []string{"nvd"}, Signals: []string{}},
		},
		{
			name: "high: P1, in by high",
			f:    Facts{Score: score(7.5), CVSSSource: "nvd", MemberLevel: MemberNone},
			want: Outcome{Band: High, Applicable: true, Rule: "high", Priority: P1, Inputs: []string{"nvd"}, Signals: []string{}},
		},
		{
			name: "kev on a medium: P0, in by kev",
			f:    Facts{Score: score(5.3), CVSSSource: "nvd", KEV: true, MemberLevel: MemberNone},
			want: Outcome{Band: Medium, Applicable: true, Rule: "kev", Priority: P0, Inputs: []string{"kev"}, Signals: []string{"kev"}},
		},
		{
			name: "kev on a critical: P0 with kev, the source and epss",
			f:    Facts{Score: score(9.8), CVSSSource: "nvd", KEV: true, EPSSPercentile: score(0.999), MemberLevel: MemberNone},
			want: Outcome{Band: Critical, Applicable: true, Rule: "critical", Priority: P0, Inputs: []string{"kev", "nvd", "epss"}, Signals: []string{"epss", "kev"}},
		},
		{
			name: "window with an epss signal: P2, in by medium-signal",
			f:    Facts{Score: score(6.5), CVSSSource: "nvd", EPSSPercentile: score(0.95), MemberLevel: MemberNone},
			want: Outcome{Band: Medium, Applicable: true, Rule: "medium-signal", Priority: P2, Inputs: []string{"nvd", "epss"}, Signals: []string{"epss"}},
		},
		{
			name: "window with the graph signal: P2",
			f:    Facts{Score: score(6.1), CVSSSource: "osv", OnCuratedList: true, OnRuntimePath: true, MemberLevel: MemberNone},
			want: Outcome{Band: Medium, Applicable: true, Rule: "medium-signal", Priority: P2, Inputs: []string{"osv", "graph"}, Signals: []string{"graph"}},
		},
		{
			name: "window without a signal: P3, out",
			f:    Facts{Score: score(6.5), CVSSSource: "nvd", MemberLevel: MemberNone},
			want: Outcome{Band: Medium, Applicable: false, Rule: "none", Priority: P3, Inputs: []string{"nvd"}, Signals: []string{}},
		},
		{
			name: "low: P4, out, the source recorded",
			f:    Facts{Score: score(3.1), CVSSSource: "nvd", MemberLevel: MemberNone},
			want: Outcome{Band: Low, Applicable: false, Rule: "none", Priority: P4, Inputs: []string{"nvd"}, Signals: []string{}},
		},
		{
			name: "medium below the window: P4, out",
			f:    Facts{Score: score(5.9), CVSSSource: "nvd", EPSSPercentile: score(0.99), MemberLevel: MemberNone},
			want: Outcome{Band: Medium, Applicable: false, Rule: "none", Priority: P4, Inputs: []string{"nvd"}, Signals: []string{"epss"}},
		},
		{
			name: "unscored: P4, out, no source",
			f:    Facts{MemberLevel: MemberNone},
			want: Outcome{Band: Unscored, Applicable: false, Rule: "none", Priority: P4, Inputs: []string{}, Signals: []string{}},
		},
		{
			name: "member exploited on a critical: P0 with member",
			f:    Facts{Score: score(9.3), CVSSSource: "nvd", MemberLevel: MemberExploited},
			want: Outcome{Band: Critical, Applicable: true, Rule: "critical", Priority: P0, Inputs: []string{"nvd", "member"}, Signals: []string{"member"}},
		},
		{
			name: "member elevated in the window: P2 with member",
			f:    Facts{Score: score(6.8), CVSSSource: "nvd", MemberLevel: MemberElevated},
			want: Outcome{Band: Medium, Applicable: true, Rule: "medium-signal", Priority: P2, Inputs: []string{"nvd", "member"}, Signals: []string{"member"}},
		},
		{
			name: "member watch is recorded only: nothing changes",
			f:    Facts{Score: score(6.8), CVSSSource: "nvd", MemberLevel: MemberWatch},
			want: Outcome{Band: Medium, Applicable: false, Rule: "none", Priority: P3, Inputs: []string{"nvd"}, Signals: []string{}},
		},
		{
			name: "no source named: osv is the default in the inputs",
			f:    Facts{Score: score(8.0), MemberLevel: MemberNone},
			want: Outcome{Band: High, Applicable: true, Rule: "high", Priority: P1, Inputs: []string{"osv"}, Signals: []string{}},
		},
	}
	for _, c := range cases {
		got := r.Evaluate(c.f)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", c.name, got, c.want)
		}
	}
}

// 2. The curated list: exact groups, prefixes with a dot, and misses.
func TestCuratedList(t *testing.T) {
	r := load(t)
	cases := map[string]bool{
		"org.yaml":                     true,
		"org.springframework":          true,
		"org.springframework.security": true,
		"com.fasterxml.jackson.core":   true,
		"org.springframeworkx":         false,
		"org.bouncycastle":             false,
		"io.netty.incubator":           false,
		"org.apache.tomcat.embed":      true,
		"ch.qos.logback.contrib":       false,
		"org.hibernate.validator":      true,
		"":                             false,
		"com.fasterxml.jackson":        true,
	}
	for group, want := range cases {
		if got := r.CuratedList(group); got != want {
			t.Errorf("%q: got %v, want %v", group, got, want)
		}
	}
}

// 3. A condition the code does not know fails to load, loudly.
func TestUnknownConditionFails(t *testing.T) {
	broken := strings.Replace(liveRules, "when: band == high", "when: band == high or cwe == 79", 1)
	_, err := Parse([]byte(broken))
	if err == nil || !strings.Contains(err.Error(), "unknown condition") {
		t.Fatalf("expected an unknown condition error, got %v", err)
	}
	broken = strings.Replace(liveRules, "P3 / Track:       score >= 6.0 and score < 7.0", "P3 / Track:       score in window", 1)
	_, err = Parse([]byte(broken))
	if err == nil || !strings.Contains(err.Error(), "unknown condition") {
		t.Fatalf("expected an unknown condition error on a priority rule, got %v", err)
	}
}

// 4. The file's own numbers are read, not assumed.
func TestBandsAndSignalsRead(t *testing.T) {
	r := load(t)
	if r.Bands.Critical != 9.0 || r.Bands.High != 7.0 || r.Bands.Medium != 4.0 {
		t.Fatalf("bands %+v", r.Bands)
	}
	if r.Signals.EPSSPercentile != 0.90 || !r.Signals.KEV || !r.Signals.FixedByUpgrade {
		t.Fatalf("signals %+v", r.Signals)
	}
	if len(r.Include) != 4 || len(r.Priority) != 5 || r.Priority[0].Name != P0 || r.Priority[4].Name != P4 {
		t.Fatalf("include %d priority %+v", len(r.Include), r.Priority)
	}
	if r.Band(score(4.0)) != Medium || r.Band(score(3.9)) != Low || r.Band(score(9.0)) != Critical || r.Band(nil) != Unscored {
		t.Fatal("band edges")
	}
}
