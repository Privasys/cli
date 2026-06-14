// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientID is the baked-in public OIDC client identifier for the CLI. The
// device flow uses no client secret and no redirect URI.
const ClientID = "privasys-cli"

// DefaultScope requests an id token, profile/email attributes, and a refresh
// token (offline_access) for silent renewal.
const DefaultScope = "openid email profile offline_access"

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceAuthResponse is the /device_authorization result (RFC 8628 + the
// Privasys qr_payload extension).
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	QRPayload               string `json:"qr_payload"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenResponse is the /token result for any grant.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// GeneratePKCE returns a random verifier and its S256 challenge.
func GeneratePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func postForm(ctx context.Context, endpoint string, form url.Values, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("unexpected response (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// BeginDevice starts a device authorization. The returned verifier must be
// kept by the caller and presented when polling.
func BeginDevice(ctx context.Context, issuer, scope, agentName string) (*DeviceAuthResponse, string, error) {
	verifier, challenge := GeneratePKCE()
	form := url.Values{
		"client_id":             {ClientID},
		"scope":                 {scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if agentName != "" {
		form.Set("agent_name", agentName)
	}
	var dr DeviceAuthResponse
	if err := postForm(ctx, issuer+"/device_authorization", form, &dr); err != nil {
		return nil, "", err
	}
	if dr.Error != "" {
		return nil, "", fmt.Errorf("%s: %s", dr.Error, dr.ErrorDescription)
	}
	if dr.Interval <= 0 {
		dr.Interval = 5
	}
	return &dr, verifier, nil
}

// PollOnce performs a single device_code token poll. On success it returns the
// tokens; while pending it returns (nil, nil); other errors are returned.
func PollOnce(ctx context.Context, issuer, deviceCode, verifier string) (*TokenResponse, time.Duration, error) {
	form := url.Values{
		"grant_type":    {deviceGrantType},
		"device_code":   {deviceCode},
		"client_id":     {ClientID},
		"code_verifier": {verifier},
	}
	var tr TokenResponse
	if err := postForm(ctx, issuer+"/token", form, &tr); err != nil {
		return nil, 0, err
	}
	switch tr.Error {
	case "":
		return &tr, 0, nil
	case "authorization_pending":
		return nil, 0, nil
	case "slow_down":
		return nil, 5 * time.Second, nil
	case "access_denied":
		return nil, 0, fmt.Errorf("the request was denied on the wallet")
	case "expired_token":
		return nil, 0, fmt.Errorf("the login request expired before approval")
	default:
		return nil, 0, fmt.Errorf("%s: %s", tr.Error, tr.ErrorDescription)
	}
}

// PollUntil polls until approval, expiry, or ctx cancellation, honoring the
// server interval and slow_down back-off.
func PollUntil(ctx context.Context, issuer, deviceCode, verifier string, interval int, expiresIn int) (*TokenResponse, error) {
	wait := time.Duration(interval) * time.Second
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the login request expired before approval")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		tr, backoff, err := PollOnce(ctx, issuer, deviceCode, verifier)
		if err != nil {
			return nil, err
		}
		if tr != nil {
			return tr, nil
		}
		if backoff > 0 {
			wait += backoff
		}
	}
}
