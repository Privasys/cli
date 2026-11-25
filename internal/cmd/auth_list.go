// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/Privasys/cli/internal/auth"
)

// credentialSummary is what `auth list` shows of a stored credential: never a
// token's value, only what is held, until when, and a fingerprint.
type credentialSummary struct {
	Issuer          string            `json:"issuer"`
	ClientID        string            `json:"client_id,omitempty"`
	Subject         string            `json:"subject,omitempty"`
	Scope           string            `json:"scope,omitempty"`
	Type            string            `json:"type"`
	Platform        string            `json:"platform,omitempty"`
	AccessToken     string            `json:"access_token_fingerprint,omitempty"`
	AccessExpiresAt *time.Time        `json:"access_expires_at,omitempty"`
	HasIDToken      bool              `json:"has_id_token"`
	HasRefreshToken bool              `json:"has_refresh_token"`
	Audiences       []audienceSummary `json:"audience_tokens,omitempty"`
}

type audienceSummary struct {
	Audience    string    `json:"audience"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// tokenFingerprint is the first 8 bytes of a token's SHA-256, in hex: enough
// to tell two tokens apart, nothing to use one with.
func tokenFingerprint(tok string) string {
	if tok == "" {
		return ""
	}
	h := sha256.Sum256([]byte(tok))
	return "sha256:" + hex.EncodeToString(h[:8])
}

func summarizeCredential(c *auth.Credential) credentialSummary {
	s := credentialSummary{
		Issuer: c.Issuer, ClientID: c.ClientID, Subject: c.Subject, Scope: c.Scope,
		Type: "wallet", Platform: c.Platform, AccessToken: tokenFingerprint(c.AccessToken),
		HasIDToken: c.IDToken != "", HasRefreshToken: c.HasRefreshToken(),
	}
	if c.IsServiceKeyAcc {
		s.Type = "service-account"
	}
	if !c.AccessExpiresAt.IsZero() {
		t := c.AccessExpiresAt
		s.AccessExpiresAt = &t
	}
	for aud, t := range c.AudienceTokens {
		s.Audiences = append(s.Audiences, audienceSummary{Audience: aud, Fingerprint: tokenFingerprint(t.AccessToken), ExpiresAt: t.ExpiresAt})
	}
	sort.Slice(s.Audiences, func(i, j int) bool { return s.Audiences[i].Audience < s.Audiences[j].Audience })
	return s
}
