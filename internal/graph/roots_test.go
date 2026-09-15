// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"testing"

	"github.com/d1gital-f/osera-line-manager/internal/book"
)

// The rule from a line: the declared groups plus the anchor's, sorted, once each;
// no components means the wide graph; a component in another form is an error.
func TestRuleFor(t *testing.T) {
	boot := book.Anchor{Group: "org.springframework.boot", Artifact: "spring-boot-dependencies", Version: "2.7.18"}

	// 1. the Wave 1 line
	rule, err := RuleFor(boot, []string{"org.springframework@5.3.39", "org.springframework.security@5.7.11"})
	if err != nil {
		t.Fatal(err)
	}
	if rule.String() != "groups:org.springframework,org.springframework.boot,org.springframework.security" {
		t.Fatalf("rule %q", rule)
	}
	if rule.Wide() {
		t.Fatal("a line with components is not wide")
	}
	if Declared(rule) != "org.springframework@5.3.39 org.springframework.security@5.7.11" {
		t.Fatalf("declared %q", Declared(rule))
	}

	// 2. a component in the anchor's own group adds no duplicate
	rule, err = RuleFor(boot, []string{"org.springframework.boot@2.7.18"})
	if err != nil || rule.String() != "groups:org.springframework.boot" {
		t.Fatalf("rule %q, %v", rule, err)
	}

	// 3. no components: the fallback
	rule, err = RuleFor(boot, nil)
	if err != nil || !rule.Wide() || rule.String() != "managed" {
		t.Fatalf("rule %q, %v", rule, err)
	}

	// 4. the older artifact form, and nonsense, are errors, not skips
	_, err = RuleFor(boot, []string{"org.springframework:spring-core@5.3.39"})
	if err == nil {
		t.Fatal("group:artifact@version must be refused")
	}
	_, err = RuleFor(boot, []string{"nonsense"})
	if err == nil {
		t.Fatal("a component without a version must be refused")
	}
}

// The roots from a managed list: the groups in, the others out, the fallback taking
// everything, a declared group the anchor does not manage giving nothing and named.
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
	rule, _ := RuleFor(boot, []string{"org.springframework@5.3.39", "org.springframework.security@5.7.11"})
	roots := selectRoots(managed, rule)
	if len(roots) != 3 || roots[0].Artifact != "spring-core" || roots[1].Artifact != "spring-boot" || roots[2].Artifact != "spring-security-core" {
		t.Fatalf("roots %+v", roots)
	}
	if len(unmanagedGroups(managed, rule)) != 0 {
		t.Fatal("both groups are managed")
	}

	// 2. a declared group the anchor does not manage gives no root and is named
	rule, _ = RuleFor(boot, []string{"org.example@9.9"})
	roots = selectRoots(managed, rule)
	if len(roots) != 1 || roots[0].Artifact != "spring-boot" {
		t.Fatalf("roots %+v", roots)
	}
	if u := unmanagedGroups(managed, rule); len(u) != 1 || u[0] != "org.example" {
		t.Fatalf("unmanaged %v", u)
	}

	// 3. the fallback: everything
	if len(selectRoots(managed, Rule{})) != 5 {
		t.Fatal("the wide rule must keep every managed artifact")
	}
}
