// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// CreateVault creates a user-facing vault (a key container) billed to the
// caller's account.
func (c *Client) CreateVault(ctx context.Context, name string) (map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/api/v1/keyvaults", map[string]string{"name": name}, &raw); err != nil {
		return nil, err
	}
	return unwrapObject(raw, "vault")
}

// ListVaults returns the caller's vaults.
func (c *Client) ListVaults(ctx context.Context) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/keyvaults", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "vaults")
}

// DeleteVault removes a vault.
func (c *Client) DeleteVault(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/keyvaults/"+url.PathEscape(id), nil, nil)
}

// ListVaultKeys returns a vault's keys (catalogue).
func (c *Client) ListVaultKeys(ctx context.Context, vaultID string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/keyvaults/"+url.PathEscape(vaultID)+"/keys", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "keys")
}

// DeleteVaultKey removes a key's catalogue entry from a vault.
func (c *Client) DeleteVaultKey(ctx context.Context, vaultID, name string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/keyvaults/"+url.PathEscape(vaultID)+"/keys/"+url.PathEscape(name), nil, nil)
}

// VaultKeyGrantResponse is the platform's response when minting a grant for a
// new key in a vault: the grant plus the constellation addressing the agent
// needs to create the material directly on the vaults.
type VaultKeyGrantResponse struct {
	Key           map[string]interface{} `json:"key"`
	Grant         string                 `json:"grant"`
	Constellation struct {
		Endpoints         []string `json:"endpoints"`
		MRENCLAVE         string   `json:"mrenclave"`
		AttestationServer string   `json:"attestation_server"`
		OIDCIssuer        string   `json:"oidc_issuer"`
		Threshold         int      `json:"threshold"`
	} `json:"constellation"`
}

// MintVaultKeyGrant asks the platform to author the policy, catalogue the key
// and mint a holder-of-key-bound grant for a new key in the vault. cnf is the
// SHA-256 thumbprint of the agent's RA-TLS leaf; the grant is bound to it.
// kind selects the policy shape ("secret" default; "wrapped-secret" grants the
// operator app's TEE principal Unwrap only — write-once), and operatorAppID
// names that app.
func (c *Client) MintVaultKeyGrant(ctx context.Context, vaultID, name, keyType, cnf string, exportable bool, kind, operatorAppID string) (*VaultKeyGrantResponse, error) {
	body := map[string]interface{}{
		"name":         name,
		"cnf_x5t_s256": cnf,
		"exportable":   exportable,
	}
	if keyType != "" {
		body["key_type"] = keyType
	}
	if kind != "" {
		body["kind"] = kind
	}
	if operatorAppID != "" {
		body["operator_app_id"] = operatorAppID
	}
	var out VaultKeyGrantResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/keyvaults/"+url.PathEscape(vaultID)+"/keys", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateVaultKeyGrant asks the platform to create a new primary version of an
// existing key (same type + policy), returning a grant bound to cnf for the new
// version's handle plus the constellation addressing.
func (c *Client) RotateVaultKeyGrant(ctx context.Context, vaultID, name, cnf string) (*VaultKeyGrantResponse, error) {
	body := map[string]interface{}{"cnf_x5t_s256": cnf}
	var out VaultKeyGrantResponse
	path := "/api/v1/keyvaults/" + url.PathEscape(vaultID) + "/keys/" + url.PathEscape(name) + "/rotate"
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
