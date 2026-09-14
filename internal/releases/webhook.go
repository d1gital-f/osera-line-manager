// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package releases

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// maxWebhookBody caps the request body; Nexus component events are under a kilobyte.
const maxWebhookBody = 1 << 20

// Event is what the line manager keeps of a Nexus component event: which
// repository, what happened, which coordinate.
type Event struct {
	Repository string
	Action     string
	Coordinate Coordinate
}

// componentEvent is the payload of the Nexus repository webhook for component events.
type componentEvent struct {
	Timestamp      string `json:"timestamp"`
	NodeID         string `json:"nodeId"`
	Initiator      string `json:"initiator"`
	RepositoryName string `json:"repositoryName"`
	Action         string `json:"action"`
	Component      struct {
		ID      string `json:"id"`
		Format  string `json:"format"`
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
	} `json:"component"`
}

// Handler receives the Nexus repository webhook. Every delivery is checked
// against the shared secret before anything is believed; a maven2 component
// event becomes an Event for onEvent, anything else is acknowledged and dropped.
func Handler(secret string, onEvent func(Event)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. the body, capped
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "reading body", http.StatusBadRequest)
			return
		}

		// 2. the signature: only Nexus knows the secret
		if !ValidSignature(secret, body, r.Header.Get("X-Nexus-Webhook-Signature")) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		// 3. the shape
		var ev componentEvent
		err = json.Unmarshal(body, &ev)
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		// 4. only maven2 components are ours; the rest is acknowledged so Nexus stops
		if ev.Component.Format != "maven2" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// 5. the event, to whoever listens
		onEvent(Event{
			Repository: ev.RepositoryName,
			Action:     ev.Action,
			Coordinate: NewCoordinate(ev.Component.Group, ev.Component.Name, ev.Component.Version),
		})
		w.WriteHeader(http.StatusOK)
	})
}

// ValidSignature reports whether sigHex is the HMAC SHA1 of body under secret,
// hex encoded, as Nexus sends it in X-Nexus-Webhook-Signature.
func ValidSignature(secret string, body []byte, sigHex string) bool {
	want, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}
