// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// StepUpAssertFunc produces the WebAuthn assertion (the JSON body the IdP's
// /fido2/vault-approval/complete expects) for the given assertion options. The
// signer holds the user's credential (the wallet / a passkey); this package and
// the CLI binary never see the signing key. In E2E the mock wallet provides it.
type StepUpAssertFunc func(ctx context.Context, optionsJSON []byte) (assertionJSON []byte, err error)

// requestExportStepUp drives the operation-bound WebAuthn step-up ceremony for
// an export of `handle` at `policyVersion`, returning the short-lived,
// amr:["webauthn"], operation-bound access token the vault's ExportKey rule
// requires. The ceremony:
//
//	POST /fido2/vault-approval/begin  {operation:"export", handle, policy_version}
//	    -> WebAuthn assertion options whose challenge IS the export binding
//	(assert the options with the user's credential)
//	POST /fido2/vault-approval/complete?challenge=<binding> -> { access_token }
//
// The vault recomputes the binding from (handle, "", policy_version, nonce, exp)
// and checks it, so the token authorises this exact export and nothing else.
func requestExportStepUp(ctx context.Context, issuer, bearer, handle string,
	policyVersion uint32, assert StepUpAssertFunc) (string, error) {
	if assert == nil {
		return "", fmt.Errorf("export requires a WebAuthn step-up but no wallet approver is wired")
	}
	beginBody, _ := json.Marshal(map[string]interface{}{
		"operation":      "export",
		"handle":         handle,
		"policy_version": policyVersion,
		"ttl_seconds":    120,
	})
	optionsJSON, err := postBearer(ctx, issuer+"/fido2/vault-approval/begin", bearer, beginBody)
	if err != nil {
		return "", fmt.Errorf("step-up begin: %w", err)
	}
	// The complete endpoint is keyed by the binding, which the IdP returns as the
	// assertion challenge (publicKey.challenge), base64url with no padding.
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil || opts.PublicKey.Challenge == "" {
		return "", fmt.Errorf("step-up begin: no challenge in options")
	}
	assertion, err := assert(ctx, optionsJSON)
	if err != nil {
		return "", fmt.Errorf("step-up assertion: %w", err)
	}
	completeURL := issuer + "/fido2/vault-approval/complete?challenge=" + url.QueryEscape(opts.PublicKey.Challenge)
	respBody, err := postBearer(ctx, completeURL, bearer, assertion)
	if err != nil {
		return "", fmt.Errorf("step-up complete: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("step-up complete: no access_token in response")
	}
	return out.AccessToken, nil
}

// postBearer POSTs a JSON body with an owner bearer and returns the response
// body, erroring on any non-2xx status.
func postBearer(ctx context.Context, u, bearer string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s -> %d: %s", u, resp.StatusCode, data)
	}
	return data, nil
}
