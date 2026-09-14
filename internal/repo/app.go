// Copyright (c) 2026 Control Plane Limited. All rights reserved.
// Built by ControlPlane for the FINOS OSERA Exchange.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultAPI is GitHub's API, replaced in tests.
const DefaultAPI = "https://api.github.com"

// TokenSource gives a token to call GitHub with.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// App is the GitHub App the line manager acts as. It mints a short lived JWT
// with the App's private key and exchanges it for an installation token, kept
// until shortly before it expires.
type App struct {
	AppID          int64
	InstallationID int64
	BaseURL        string
	HTTP           *http.Client
	key            *rsa.PrivateKey
	now            func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewApp reads the App's private key (PKCS1 or PKCS8 PEM, as GitHub hands it out).
func NewApp(appID, installationID int64, privateKeyPEM []byte, httpClient *http.Client) (*App, error) {
	// 1. the key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("the App's private key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("parsing the App's private key: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("the App's private key is not RSA")
		}
		key = rsaKey
	}

	// 2. the client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &App{
		AppID:          appID,
		InstallationID: installationID,
		BaseURL:        DefaultAPI,
		HTTP:           httpClient,
		key:            key,
		now:            time.Now,
	}, nil
}

// JWT mints the App's JSON Web Token: RS256, issued a minute ago to absorb
// clock drift, valid nine minutes, issuer the App id.
func (a *App) JWT() (string, error) {
	// 1. header and claims
	now := a.now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]int64{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": a.AppID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// 2. the signing input, then the signature
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing the JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Token returns an installation token, minted when there is none or the one
// held expires within five minutes.
func (a *App) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. the one we hold, when it still has time
	if a.token != "" && a.now().Add(5*time.Minute).Before(a.expires) {
		return a.token, nil
	}

	// 2. a new one, through the JWT
	jwt, err := a.JWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", a.BaseURL, a.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("asking for an installation token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("asking for an installation token: HTTP %d: %s", resp.StatusCode, body)
	}
	var answer struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return "", fmt.Errorf("reading the installation token: %w", err)
	}

	// 3. kept for next time
	a.token = answer.Token
	a.expires = answer.ExpiresAt
	return a.token, nil
}
