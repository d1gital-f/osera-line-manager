// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package graph

import "encoding/xml"

// xmlUnmarshal reads a POM; kept apart so the resolve file does not import xml.
func xmlUnmarshal(raw []byte, into *pom) error {
	return xml.Unmarshal(raw, into)
}
