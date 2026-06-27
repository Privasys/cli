// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// RegistrySecretResponse is the platform's response when minting a grant for an
// app's private-image pull credential: the grant plus the constellation
// addressing the owner's client needs to push the token material directly.
type RegistrySecretResponse struct {
	Handle        string `json:"handle"`
	Grant         string `json:"grant"`
	Constellation struct {
		Endpoints         []string `json:"endpoints"`
		MRENCLAVE         string   `json:"mrenclave"`
		AttestationServer string   `json:"attestation_server"`
		OIDCIssuer        string   `json:"oidc_issuer"`
		Threshold         int      `json:"threshold"`
	} `json:"constellation"`
}

// AddRegistrySecret asks the platform to author the pull-credential policy (the
// in-TD manager runtime gets ExportKey at pull time; the owner keeps control),
// mint a holder-of-key-bound grant, and record the handle on the app. cnf is the
// SHA-256 thumbprint of the owner's RA-TLS leaf; the grant is bound to it so only
// this client can create the material. enclaveID is optional (defaults to the
// app's assigned enclave).
func (c *Client) AddRegistrySecret(ctx context.Context, appID, name, cnf, enclaveID string) (*RegistrySecretResponse, error) {
	body := map[string]interface{}{"cnf_x5t_s256": cnf}
	if name != "" {
		body["name"] = name
	}
	if enclaveID != "" {
		body["enclave_id"] = enclaveID
	}
	var out RegistrySecretResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+url.PathEscape(appID)+"/registry-secret", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRegistrySecret reports whether the app has a pull credential configured
// (never the material).
func (c *Client) GetRegistrySecret(ctx context.Context, appID string) (map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+url.PathEscape(appID)+"/registry-secret", &raw); err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// DeleteRegistrySecret clears the app's pull credential so it pulls anonymously.
func (c *Client) DeleteRegistrySecret(ctx context.Context, appID string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/apps/"+url.PathEscape(appID)+"/registry-secret", nil, nil)
}
