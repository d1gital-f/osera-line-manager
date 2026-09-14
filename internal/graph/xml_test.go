// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import "testing"

// A POM declared as iso-8859-1 with a Latin-1 byte in it reads as UTF-8; an
// encoding nobody uses is refused by name.
func TestXMLUnmarshalLatin1(t *testing.T) {
	// 1. the Spring case: an old POM on Central, é as one byte
	raw := []byte("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version><name>caf\xe9</name></project>")
	var p pom
	if err := xmlUnmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.ArtifactID != "a" {
		t.Fatalf("artifact %q", p.ArtifactID)
	}

	// 2. an encoding the reader does not know
	raw = []byte("<?xml version=\"1.0\" encoding=\"EBCDIC-CP-US\"?><project/>")
	if err := xmlUnmarshal(raw, &p); err == nil {
		t.Fatal("unknown encoding accepted")
	}
}
