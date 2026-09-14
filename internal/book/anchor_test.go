// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package book

import "testing"

// The anchor as the line file writes it.
func TestParseAnchor(t *testing.T) {
	a, err := ParseAnchor("org.springframework.boot:spring-boot-dependencies@2.7.18")
	if err != nil {
		t.Fatal(err)
	}
	if a.Group != "org.springframework.boot" || a.Artifact != "spring-boot-dependencies" || a.Version != "2.7.18" {
		t.Fatalf("anchor %+v", a)
	}
	if a.String() != "org.springframework.boot:spring-boot-dependencies@2.7.18" {
		t.Fatalf("string %s", a)
	}
	for _, bad := range []string{"", "gson@2.8.8", "org.example:lib", "org.example:@1", ":lib@1"} {
		if _, err := ParseAnchor(bad); err == nil {
			t.Fatalf("%q must not parse", bad)
		}
	}
}
