// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package mockwallet is a software FIDO2/WebAuthn authenticator that stands in
// for the Privasys Wallet in end-to-end tests. It completes the IdP's device
// authorization the way a phone would, so the CLI's onboarding flow
// (`auth begin` / `auth_begin` -> approve -> `auth poll`) can be driven without
// a real device.
//
// The WebAuthn cryptography is handled by github.com/descope/virtualwebauthn,
// the matched client for the IdP's server-side github.com/go-webauthn/webauthn.
// This package only adds the Privasys-specific glue: the `/fido2/*` ceremony
// endpoints, the `session_id` binding, and the device-approver that maps a
// user_code to the in-flight session.
//
// It is a TEST helper, never compiled into the privasys binary.
package mockwallet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/descope/virtualwebauthn"
)

// Wallet is a single software authenticator identity (one credential).
type Wallet struct {
	auth       virtualwebauthn.Authenticator
	cred       virtualwebauthn.Credential
	userHandle []byte
	hc         *http.Client
	rp         virtualwebauthn.RelyingParty // set at registration; reused for assertions
}

// New creates a fresh wallet identity (a new P-256 credential + user handle).
// Each E2E run gets a new test user, which keeps runs independent.
func New() *Wallet {
	return &Wallet{
		auth:       virtualwebauthn.NewAuthenticator(),
		cred:       virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
		userHandle: randBytes(32),
		hc:         http.DefaultClient,
	}
}

// qrInfo is the subset of the device QR payload the ceremony needs.
type qrInfo struct {
	SessionID string
	RpID      string
	Origin    string
}

// parseQRPayload decodes the device QR universal link
// (https://privasys.id/scp?p=<base64url(JSON)>) into its session + RP fields.
func parseQRPayload(qr string) (qrInfo, error) {
	u, err := url.Parse(qr)
	if err != nil {
		return qrInfo{}, fmt.Errorf("qr_payload not a URL: %w", err)
	}
	p := u.Query().Get("p")
	if p == "" {
		return qrInfo{}, fmt.Errorf("qr_payload missing the 'p' parameter")
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return qrInfo{}, fmt.Errorf("qr_payload base64: %w", err)
	}
	var m struct {
		SessionID string `json:"sessionId"`
		RpID      string `json:"rpId"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return qrInfo{}, fmt.Errorf("qr_payload json: %w", err)
	}
	rpID := m.RpID
	if rpID == "" {
		rpID = m.Origin
	}
	if rpID == "" || m.SessionID == "" {
		return qrInfo{}, fmt.Errorf("qr_payload missing sessionId/rpId")
	}
	// The wallet authenticates the WebAuthn ceremony against https://<rpId>,
	// matching the IdP's go-webauthn origin configuration.
	return qrInfo{SessionID: m.SessionID, RpID: rpID, Origin: "https://" + rpID}, nil
}

// ApproveDevice completes a pending device authorization for the given
// user_code: it looks up the device's session and registers a fresh credential
// bound to it, which marks the session authenticated (the CLI's poll then
// receives a token). idpURL is the IdP origin (no trailing slash).
func (w *Wallet) ApproveDevice(ctx context.Context, idpURL, userCode string) error {
	var lk struct {
		QRPayload string `json:"qr_payload"`
		Status    string `json:"status"`
	}
	if err := w.getJSON(ctx, idpURL+"/device/lookup?user_code="+url.QueryEscape(userCode), &lk); err != nil {
		return fmt.Errorf("device lookup: %w", err)
	}
	info, err := parseQRPayload(lk.QRPayload)
	if err != nil {
		return err
	}
	rp := virtualwebauthn.RelyingParty{Name: "Privasys", ID: info.RpID, Origin: info.Origin}
	return w.register(ctx, idpURL, rp, info.SessionID, "e2e-"+hex.EncodeToString(randBytes(4)))
}

// register runs the FIDO2 registration ceremony bound to sessionID, creating
// the user and completing the device's AuthSession.
func (w *Wallet) register(ctx context.Context, idpURL string, rp virtualwebauthn.RelyingParty, sessionID, displayName string) error {
	beginURL := idpURL + "/fido2/register/begin?session_id=" + url.QueryEscape(sessionID)
	optsJSON, err := w.postString(ctx, beginURL, map[string]string{
		"userName":   displayName,
		"userHandle": base64.RawURLEncoding.EncodeToString(w.userHandle),
	})
	if err != nil {
		return fmt.Errorf("register/begin: %w", err)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(optsJSON)
	if err != nil {
		return fmt.Errorf("parse attestation options: %w", err)
	}
	resp := virtualwebauthn.CreateAttestationResponse(rp, w.auth, w.cred, *opts)

	challenge := base64.RawURLEncoding.EncodeToString(opts.Challenge)
	completeURL := idpURL + "/fido2/register/complete?challenge=" + url.QueryEscape(challenge)
	if _, err := w.postString(ctx, completeURL, json.RawMessage(resp)); err != nil {
		return fmt.Errorf("register/complete: %w", err)
	}
	w.auth.AddCredential(w.cred)
	w.rp = rp
	return nil
}

// AssertStepUp signs a WebAuthn assertion for the given options with this
// wallet's credential. It matches secrets.StepUpAssertFunc, so the CLI's export
// flow can hand it the IdP's /fido2/vault-approval/begin options and get back
// the assertion body the /complete step expects — exactly what the Privasys
// Wallet's "Vault approvals" screen will do for a human. The wallet must have
// registered first (ApproveDevice), so its credential exists for the user.
func (w *Wallet) AssertStepUp(_ context.Context, optionsJSON []byte) ([]byte, error) {
	if w.rp.ID == "" {
		return nil, fmt.Errorf("wallet has no registered credential; call ApproveDevice first")
	}
	opts, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	if err != nil {
		return nil, fmt.Errorf("parse assertion options: %w", err)
	}
	resp := virtualwebauthn.CreateAssertionResponse(w.rp, w.auth, w.cred, *opts)
	return []byte(resp), nil
}

// --- HTTP helpers ---

func (w *Wallet) getJSON(ctx context.Context, u string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GET %s -> %d: %s", u, resp.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

// postString posts body as JSON and returns the response body. body may be a
// json.RawMessage (sent verbatim) or any JSON-marshalable value.
func (w *Wallet) postString(ctx context.Context, u string, body interface{}) (string, error) {
	var buf []byte
	switch b := body.(type) {
	case json.RawMessage:
		buf = b
	default:
		var err error
		if buf, err = json.Marshal(body); err != nil {
			return "", err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("POST %s -> %d: %s", u, resp.StatusCode, out)
	}
	return string(out), nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
