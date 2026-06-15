// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// expirySkew is how long before expiry a token is considered stale.
const expirySkew = 60 * time.Second

// AccessToken returns a valid access token for the issuer, honoring (in order):
// PRIVASYS_ACCESS_TOKEN, PRIVASYS_SERVICE_KEY, a stored service account, then a
// stored user credential (refreshing silently when needed).
func AccessToken(ctx context.Context, issuer string) (string, error) {
	if t := os.Getenv("PRIVASYS_ACCESS_TOKEN"); t != "" {
		return t, nil
	}

	if sk := os.Getenv("PRIVASYS_SERVICE_KEY"); sk != "" {
		k, err := loadServiceKeyFromEnv(sk)
		if err != nil {
			return "", err
		}
		tr, err := MintServiceAccountToken(ctx, issuer, k, PlatformAudience)
		if err != nil {
			return "", err
		}
		return tr.AccessToken, nil
	}

	cred, err := Load(issuer)
	if err != nil {
		return "", err
	}

	// Service-account credential: mint on demand (no refresh token involved).
	if cred.IsServiceKeyAcc && cred.ServiceKey != "" {
		if cred.AccessToken != "" && time.Until(cred.AccessExpiresAt) > expirySkew {
			return cred.AccessToken, nil
		}
		k, err := ParseServiceKey([]byte(cred.ServiceKey))
		if err != nil {
			return "", err
		}
		tr, err := MintServiceAccountToken(ctx, issuer, k, PlatformAudience)
		if err != nil {
			return "", err
		}
		cred.AccessToken = tr.AccessToken
		cred.AccessExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
		_ = Save(cred)
		return tr.AccessToken, nil
	}

	// User credential: use the cached access token while fresh, else refresh.
	if cred.AccessToken != "" && time.Until(cred.AccessExpiresAt) > expirySkew {
		return cred.AccessToken, nil
	}
	if cred.RefreshToken == "" {
		return "", ErrNotLoggedIn
	}
	tr, err := refresh(ctx, issuer, cred.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("session refresh failed (run `privasys auth login`): %w", err)
	}
	cred.AccessToken = tr.AccessToken
	cred.IDToken = tr.IDToken
	cred.AccessExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if tr.RefreshToken != "" {
		cred.RefreshToken = tr.RefreshToken
	}
	if err := Save(cred); err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

func refresh(ctx context.Context, issuer, refreshToken string) (*TokenResponse, error) {
	return refreshWithScope(ctx, issuer, refreshToken, "")
}

func refreshWithScope(ctx context.Context, issuer, refreshToken, scope string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ClientID},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	var tr TokenResponse
	if err := postForm(ctx, issuer+"/token", form, &tr); err != nil {
		return nil, err
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%s: %s", tr.Error, tr.ErrorDescription)
	}
	return &tr, nil
}

// AccessTokenForAudience mints an access token bound to a specific audience
// (e.g. "attestation-server") so the CLI can call that resource server
// directly. For user sessions it uses the refresh grant with an `audience:`
// scope (the rotated refresh token keeps the original scope); for service
// accounts it mints via JWT-bearer. PRIVASYS_ACCESS_TOKEN is returned as-is.
func AccessTokenForAudience(ctx context.Context, issuer, audience string) (string, error) {
	if t := os.Getenv("PRIVASYS_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	if sk := os.Getenv("PRIVASYS_SERVICE_KEY"); sk != "" {
		k, err := loadServiceKeyFromEnv(sk)
		if err != nil {
			return "", err
		}
		tr, err := MintServiceAccountToken(ctx, issuer, k, audience)
		if err != nil {
			return "", err
		}
		return tr.AccessToken, nil
	}
	cred, err := Load(issuer)
	if err != nil {
		return "", err
	}
	if cred.IsServiceKeyAcc && cred.ServiceKey != "" {
		k, err := ParseServiceKey([]byte(cred.ServiceKey))
		if err != nil {
			return "", err
		}
		tr, err := MintServiceAccountToken(ctx, issuer, k, audience)
		if err != nil {
			return "", err
		}
		return tr.AccessToken, nil
	}
	if cred.RefreshToken == "" {
		return "", ErrNotLoggedIn
	}
	tr, err := refreshWithScope(ctx, issuer, cred.RefreshToken, "openid audience:"+audience)
	if err != nil {
		return "", err
	}
	// Persist the rotated refresh token (single-use rotation).
	if tr.RefreshToken != "" {
		cred.RefreshToken = tr.RefreshToken
		_ = Save(cred)
	}
	return tr.AccessToken, nil
}

func loadServiceKeyFromEnv(v string) (*ServiceKey, error) {
	if strings.HasPrefix(strings.TrimSpace(v), "{") {
		return ParseServiceKey([]byte(v))
	}
	data, err := os.ReadFile(v)
	if err != nil {
		return nil, fmt.Errorf("read PRIVASYS_SERVICE_KEY file: %w", err)
	}
	return ParseServiceKey(data)
}

// Claims decodes (without verifying) the payload of a JWT. Used for `whoami`
// against the caller's own token; trust comes from the token having been
// minted into the keychain by a verified flow, not from local re-validation.
func Claims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	return m, nil
}
