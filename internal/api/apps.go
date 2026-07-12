// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// do performs an authenticated request with an optional JSON body and decodes
// the JSON response into out (out may be nil to discard).
func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("not authorized (%d) — check your login and account access", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// CreateApp creates an app from the given request body (CreateAppRequest shape).
func (c *Client) CreateApp(ctx context.Context, body map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InstanceSizes lists the Confidential-* container VM sizes and rates
// (GET /api/v1/catalog/instance-sizes).
func (c *Client) InstanceSizes(ctx context.Context) ([]map[string]interface{}, error) {
	var out struct {
		Sizes []map[string]interface{} `json:"sizes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/catalog/instance-sizes", nil, &out); err != nil {
		return nil, err
	}
	return out.Sizes, nil
}

// UpdateStoreListing sets an app's App Store listing fields (PUT
// /apps/{id}/store). A Description and Category are required before the app can
// be deployed or published. Only the keys present in fields are sent.
func (c *Client) UpdateStoreListing(ctx context.Context, id string, fields map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPut, "/api/v1/apps/"+id+"/store", fields, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// VaultExportTarget describes where an app's owner-exportable data key lives,
// so the CLI can export it directly from the vaults over RA-TLS.
type VaultExportTarget struct {
	Handle            string   `json:"handle"`
	Endpoints         []string `json:"endpoints"`
	MRENCLAVE         string   `json:"mrenclave"`
	AttestationServer string   `json:"attestation_server"`
	Threshold         int      `json:"threshold"`
	RequireStepUp     bool     `json:"require_step_up"`
}

// GetVaultExportTarget resolves the vault target for exporting an app's data
// key (GET /apps/{id}/vault-export-target). Owner-only on the server.
func (c *Client) GetVaultExportTarget(ctx context.Context, id string) (*VaultExportTarget, error) {
	var out VaultExportTarget
	if err := c.do(ctx, http.MethodGet, "/api/v1/apps/"+id+"/vault-export-target", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteApp deletes an app by id.
func (c *Client) DeleteApp(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/apps/"+id, nil, nil)
}

// CheckName reports whether an app name is available.
func (c *Client) CheckName(ctx context.Context, name string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/apps/check-name?name="+name, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UploadCwasm uploads a .cwasm artifact for a wasm app (multipart field "file").
func (c *Client) UploadCwasm(ctx context.Context, id, path string) (map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return nil, err
	}
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/apps/"+id+"/upload", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("upload error %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out map[string]interface{}
	json.Unmarshal(data, &out)
	return out, nil
}

// ListVersions returns an app's versions.
func (c *Client) ListVersions(ctx context.Context, id string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/versions", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "versions")
}

// CreateVersion records a new version. The body is source-aware (the server
// branches on the app's source_type): {commit_url} for github, {image} for
// package, {channel} for cloud_image, plus an optional {version} semver.
func (c *Client) CreateVersion(ctx context.Context, id string, body map[string]string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+id+"/versions", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeployVersion deploys a version to an enclave. instanceSize optionally sets
// this deployment's Confidential-* size (empty = the app's default); a
// redeploy with a different size is the resize primitive.
func (c *Client) DeployVersion(ctx context.Context, id, versionID, enclaveID, instanceSize string) (map[string]interface{}, error) {
	body := map[string]string{"enclave_id": enclaveID}
	if instanceSize != "" {
		body["instance_size"] = instanceSize
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost,
		"/api/v1/apps/"+id+"/versions/"+versionID+"/deploy",
		body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// StageProfile stages a pending vault key profile for a version's measurement
// (MRTD + image digest on the target enclave). Owner-only.
func (c *Client) StageProfile(ctx context.Context, id, versionID, enclaveID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost,
		"/api/v1/apps/"+id+"/versions/"+versionID+"/stage",
		map[string]string{"enclave_id": enclaveID}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListPending returns the pending vault key profiles for a version, with the
// staged measurement and per-vault K-of-N progress. Owner-only.
func (c *Client) ListPending(ctx context.Context, id, versionID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/versions/"+versionID+"/pending", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PromoteProfile promotes (approves) a staged profile, authorizing the new
// measurement so the vault releases the data key to it. Owner-only.
//
// approvalTokens carries any separation-of-duties co-sign JWTs the policy
// requires (item 3 / G.2): each must be a fresh approval token issued for the
// role-based Manager(0) by a SECOND team approver. Empty for apps that have not
// opted into co-sign (the default).
func (c *Client) PromoteProfile(ctx context.Context, id, versionID string, pendingID int, approvalTokens ...string) (map[string]interface{}, error) {
	var out map[string]interface{}
	body := map[string]interface{}{"pending_id": pendingID}
	if len(approvalTokens) > 0 {
		body["approval_tokens"] = approvalTokens
	}
	if err := c.do(ctx, http.MethodPost,
		"/api/v1/apps/"+id+"/versions/"+versionID+"/promote",
		body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetVaultCosign toggles separation-of-duties co-sign on promote for an app
// (item 3 / G.2). Owner-only.
func (c *Client) SetVaultCosign(ctx context.Context, id string, require bool) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPatch,
		"/api/v1/apps/"+id+"/vault-cosign",
		map[string]bool{"require_cosign": require}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeProfile drops a staged-but-unpromoted profile. Owner-only.
func (c *Client) RevokeProfile(ctx context.Context, id, versionID string, pendingID int) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost,
		"/api/v1/apps/"+id+"/versions/"+versionID+"/revoke",
		map[string]int{"pending_id": pendingID}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RotateKey rotates the app's vault-backed volume KEK without re-encrypting
// data: it provisions a new key generation, re-keys the running container's
// LUKS keyslots online, advances the key handle, and retires the old
// generation. enclaveID is the enclave the app currently runs on. Owner-only.
func (c *Client) RotateKey(ctx context.Context, id, versionID, enclaveID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost,
		"/api/v1/apps/"+id+"/versions/"+versionID+"/rotate-key",
		map[string]string{"enclave_id": enclaveID}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MigrateConstellation moves the app's vault-backed volume key onto a new
// constellation without re-encrypting data (graceful vault rotation). Empty
// targetConstellationID = the active constellation. Owner-only.
func (c *Client) MigrateConstellation(ctx context.Context, id, targetConstellationID string) (map[string]interface{}, error) {
	body := map[string]string{}
	if targetConstellationID != "" {
		body["target_constellation_id"] = targetConstellationID
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost,
		"/api/v1/apps/"+id+"/migrate-constellation", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDeployments returns an app's deployments.
func (c *Client) ListDeployments(ctx context.Context, id string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/deployments", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "deployments")
}

// StopDeployment stops a running deployment.
func (c *Client) StopDeployment(ctx context.Context, id, deploymentID string, force bool) (map[string]interface{}, error) {
	path := "/api/v1/apps/" + id + "/deployments/" + deploymentID + "/stop"
	if force {
		path += "?force=true"
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, path, map[string]interface{}{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CompatibleEnclaves lists enclaves an app can be deployed to.
func (c *Client) CompatibleEnclaves(ctx context.Context, id string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/compatible-enclaves", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "enclaves")
}

// Schema returns the app's exported function schema (unwraps {status, schema}).
func (c *Client) Schema(ctx context.Context, id string) (map[string]interface{}, error) {
	var env map[string]json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/schema", &env); err != nil {
		return nil, err
	}
	if s, ok := env["schema"]; ok {
		var out map[string]interface{}
		if err := json.Unmarshal(s, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	out := map[string]interface{}{}
	for k, v := range env {
		var anyv interface{}
		json.Unmarshal(v, &anyv)
		out[k] = anyv
	}
	return out, nil
}

// Rpc invokes an app tool by name through the control-plane relay
// (POST /api/v1/apps/{id}/rpc/{fn}). Used for owner config/management operations
// (configure, actions, status polling); high-throughput data calls use direct
// RA-TLS via `app call`.
func (c *Client) Rpc(ctx context.Context, id, fn string, body interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+id+"/rpc/"+fn, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MCP returns the app's MCP tool manifest.
func (c *Client) MCP(ctx context.Context, id string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/mcp", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// (App function calls are direct over RA-TLS — see internal/ratls.Call — not
// proxied through the control plane.)

// ActiveDeploymentHost returns the gateway FQDN of the app's active deployment
// (the SNI the client connects to for direct RA-TLS). The hostname lives on
// the deployment record, not the app record.
func (c *Client) ActiveDeploymentHost(ctx context.Context, appID string) (string, error) {
	deps, err := c.ListDeployments(ctx, appID)
	if err != nil {
		return "", err
	}
	var fallback string
	for _, d := range deps {
		h, _ := d["hostname"].(string)
		if h == "" {
			continue
		}
		switch s, _ := d["status"].(string); s {
		case "active", "deployed", "running":
			return h, nil
		}
		if fallback == "" {
			fallback = h
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("app has no deployment with a hostname (is it deployed?)")
}

// ListBuilds returns an app's build jobs.
func (c *Client) ListBuilds(ctx context.Context, id string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+id+"/builds", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "builds")
}
