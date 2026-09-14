// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// The rule from a line: the components' groups plus the anchor's, sorted, once each;
// no components means the wide graph.
func TestRuleFor(t *testing.T) {
	boot := book.Anchor{Group: "org.springframework.boot", Artifact: "spring-boot-dependencies", Version: "2.7.18"}

	// 1. the Wave 1 line
	rule := RuleFor(boot, []string{"org.springframework:spring-core@5.3.39", "org.springframework.security:spring-security-core@5.7.11"})
	if rule.String() != "groups:org.springframework,org.springframework.boot,org.springframework.security" {
		t.Fatalf("rule %q", rule)
	}
	if rule.Wide() {
		t.Fatal("a line with components is not wide")
	}

	// 2. a component in the anchor's own group adds no duplicate
	rule = RuleFor(boot, []string{"org.springframework.boot:spring-boot@2.7.18"})
	if rule.String() != "groups:org.springframework.boot" {
		t.Fatalf("rule %q", rule)
	}

	// 3. no components: the fallback
	rule = RuleFor(boot, nil)
	if !rule.Wide() || rule.String() != "managed" {
		t.Fatalf("rule %q", rule)
	}

	// 4. a component that does not parse is skipped, not fatal
	rule = RuleFor(boot, []string{"nonsense", "org.springframework:spring-core@5.3.39"})
	if rule.String() != "groups:org.springframework,org.springframework.boot" {
		t.Fatalf("rule %q", rule)
	}
}

// The roots from a managed list: the groups in, the others out, a declared component
// the anchor does not manage added at its version, the fallback taking everything.
func TestSelectRoots(t *testing.T) {
	managed := []Component{
		{Group: "org.springframework", Artifact: "spring-core", Version: "5.3.39"},
		{Group: "org.springframework.boot", Artifact: "spring-boot", Version: "2.7.18"},
		{Group: "org.apache.kafka", Artifact: "kafka-clients", Version: "3.1.2"},
		{Group: "org.springframework.security", Artifact: "spring-security-core", Version: "5.7.11"},
		{Group: "io.netty", Artifact: "netty-all", Version: "4.1.100.Final"},
	}
	boot := book.Anchor{Group: "org.springframework.boot", Artifact: "spring-boot-dependencies", Version: "2.7.18"}

	// 1. the Wave 1 rule: three of five, in the anchor's order
	rule := RuleFor(boot, []string{"org.springframework:spring-core@5.3.39", "org.springframework.security:spring-security-core@5.7.11"})
	roots := selectRoots(managed, rule)
	if len(roots) != 3 || roots[0].Artifact != "spring-core" || roots[1].Artifact != "spring-boot" || roots[2].Artifact != "spring-security-core" {
		t.Fatalf("roots %+v", roots)
	}

	// 2. a declared component the anchor does not manage becomes a root at its declared version
	rule = RuleFor(boot, []string{"org.example:extra@9.9"})
	roots = selectRoots(managed, rule)
	if len(roots) != 2 || roots[0].Artifact != "spring-boot" || roots[1].Artifact != "extra" || roots[1].Version != "9.9" {
		t.Fatalf("roots %+v", roots)
	}

	// 3. a declared component the anchor manages is not added twice
	rule = RuleFor(boot, []string{"org.springframework:spring-core@5.3.39"})
	roots = selectRoots(managed, rule)
	if len(roots) != 2 {
		t.Fatalf("roots %+v", roots)
	}

	// 4. the fallback: everything
	if len(selectRoots(managed, Rule{})) != 5 {
		t.Fatal("the wide rule must keep every managed artifact")
	}
}
