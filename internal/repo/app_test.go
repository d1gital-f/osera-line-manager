// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, pemBytes
}

// 1. The JWT has three parts, an RS256 header, the three claims, and a signature the key verifies.
func TestJWT(t *testing.T) {
	key, pemBytes := testKey(t)
	app, err := NewApp(4940647, 161618047, pemBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	app.now = func() time.Time { return fixed }
	token, err := app.JWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%d parts", len(parts))
	}
	var header map[string]string
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(raw, &header); err != nil || header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("header %s %v", raw, err)
	}
	var claims map[string]int64
	raw, _ = base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != 4940647 || claims["iat"] != fixed.Unix()-60 || claims["exp"] != fixed.Unix()+540 {
		t.Fatalf("claims %v", claims)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// 2. A PKCS8 key is accepted too, garbage is refused.
func TestNewAppKeys(t *testing.T) {
	key, _ := testKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if _, err := NewApp(1, 1, pemBytes, nil); err != nil {
		t.Fatalf("PKCS8 refused: %v", err)
	}
	if _, err := NewApp(1, 1, []byte("not a key"), nil); err == nil {
		t.Fatal("garbage accepted as a key")
	}
}

// 3. The installation token is asked for with the JWT, then held until it nears expiry.
func TestToken(t *testing.T) {
	_, pemBytes := testKey(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/161618047/access_tokens" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
			t.Errorf("authorization %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_test","expires_at":"2026-09-14T13:00:00Z"}`))
	}))
	defer server.Close()
	app, err := NewApp(4940647, 161618047, pemBytes, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	app.BaseURL = server.URL
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	app.now = func() time.Time { return now }

	token, err := app.Token(context.Background())
	if err != nil || token != "ghs_test" {
		t.Fatalf("token %q %v", token, err)
	}
	if _, err := app.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("%d calls, the token should have been held", calls)
	}

	// four minutes before expiry: a new one
	now = time.Date(2026, 9, 14, 12, 56, 0, 0, time.UTC)
	if _, err := app.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("%d calls, a token near expiry should be replaced", calls)
	}
}
