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
// stored user sign-in (refreshing silently when needed). The token is for the
// run's platform audience (CurrentPlatformAudience), from that platform's own
// sign-in.
func AccessToken(ctx context.Context, issuer string) (string, error) {
	if t := os.Getenv("PRIVASYS_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	aud := CurrentPlatformAudience()

	if sk := os.Getenv("PRIVASYS_SERVICE_KEY"); sk != "" {
		k, err := loadServiceKeyFromEnv(sk)
		if err != nil {
			return "", err
		}
		tr, err := MintServiceAccountToken(ctx, issuer, k, aud)
		if err != nil {
			return "", err
		}
		return tr.AccessToken, nil
	}
	return platformToken(ctx, issuer, aud)
}

// signInFor is the stored sign-in that gives tokens for platform. A service
// account activated on the production platform mints for any audience (a
// JWT-bearer grant, no refresh), as it always did.
func signInFor(issuer, platform string) (*Credential, error) {
	cred, err := LoadFor(issuer, platform)
	if err == nil {
		return cred, nil
	}
	if platform != PlatformAudience {
		if sa, serr := LoadFor(issuer, PlatformAudience); serr == nil && sa.IsServiceKeyAcc && sa.ServiceKey != "" {
			return sa, nil
		}
	}
	return nil, err
}

// platformToken is a token for the platform aud, from aud's own sign-in only.
func platformToken(ctx context.Context, issuer, aud string) (string, error) {
	var tok string
	err := withCredentialLock(func() error {
		cred, err := signInFor(issuer, aud)
		if err != nil {
			return err
		}
		own := slotKey(issuer, cred.Platform) == slotKey(issuer, aud)
		if own && cred.AccessToken != "" && time.Until(cred.AccessExpiresAt) > expirySkew {
			tok = cred.AccessToken
			return nil
		}
		if cred.IsServiceKeyAcc && cred.ServiceKey != "" {
			k, err := ParseServiceKey([]byte(cred.ServiceKey))
			if err != nil {
				return err
			}
			tr, err := MintServiceAccountToken(ctx, issuer, k, aud)
			if err != nil {
				return err
			}
			tok = tr.AccessToken
			if own {
				cred.AccessToken = tr.AccessToken
				cred.AccessExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
				_ = Save(cred)
			}
			return nil
		}
		if cred.RefreshToken == "" {
			return &NotSignedInError{Platform: platformName(aud)}
		}
		// The production sign-in refreshes as it always did; another
		// platform's names its own audience, which is the one it was made for.
		scope := ""
		if aud != PlatformAudience {
			scope = "openid audience:" + aud
		}
		tr, err := refreshWithScope(ctx, issuer, cred.RefreshToken, scope)
		if err != nil {
			return fmt.Errorf("the sign-in to %s could not be refreshed (run `privasys auth login` with the same --endpoint or --test): %w",
				platformName(aud), err)
		}
		cred.AccessToken = tr.AccessToken
		cred.IDToken = tr.IDToken
		cred.AccessExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
		if tr.RefreshToken != "" {
			cred.RefreshToken = tr.RefreshToken
		}
		if err := Save(cred); err != nil {
			return err
		}
		tok = tr.AccessToken
		return nil
	})
	return tok, err
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

// VaultTokenFor is a bearer for vaults that accept audience ("" = the
// default vault audience): each constellation's vaults accept one, which the
// control plane reports with its addressing.
func VaultTokenFor(ctx context.Context, issuer, audience string) (string, error) {
	if audience == "" {
		audience = VaultAudience
	}
	return AccessTokenForAudience(ctx, issuer, audience)
}

// AccessTokenForAudience mints an access token bound to a specific audience
// (e.g. "attestation-server", or a vault audience) so the CLI can call that
// resource server directly. A platform's audience comes only from that
// platform's own sign-in; any other from this run's platform sign-in. For user
// sessions it uses the refresh grant with an `audience:` scope (the rotated
// refresh token keeps the original scope); for service accounts it mints via
// JWT-bearer. PRIVASYS_ACCESS_TOKEN is returned as-is.
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
	platform := CurrentPlatformAudience()
	if isPlatformAudience(audience) {
		platform = audience
	}
	var tok string
	err := withCredentialLock(func() error {
		cred, err := signInFor(issuer, platform)
		if err != nil {
			return err
		}
		if cred.IsServiceKeyAcc && cred.ServiceKey != "" {
			k, err := ParseServiceKey([]byte(cred.ServiceKey))
			if err != nil {
				return err
			}
			tr, err := MintServiceAccountToken(ctx, issuer, k, audience)
			if err != nil {
				return err
			}
			tok = tr.AccessToken
			return nil
		}
		if cred.RefreshToken == "" {
			return &NotSignedInError{Platform: platformName(platform)}
		}
		tr, err := refreshWithScope(ctx, issuer, cred.RefreshToken, "openid audience:"+audience)
		if err != nil {
			return fmt.Errorf("the sign-in to %s could not be refreshed for %s (run `privasys auth login` with the same --endpoint or --test): %w",
				platformName(platform), audience, err)
		}
		// Persist the rotated refresh token (single-use rotation).
		if tr.RefreshToken != "" {
			cred.RefreshToken = tr.RefreshToken
			if err := Save(cred); err != nil {
				return err
			}
		}
		tok = tr.AccessToken
		return nil
	})
	return tok, err
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
