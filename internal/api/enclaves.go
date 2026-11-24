// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ListEnclaves returns the platform's enclave fleet. This is a platform-manager
// view (GET /api/v1/admin/enclaves, role privasys-platform:manager); callers
// without that role get 403 (exit code 4). teeType/status filter the result
// (server returns the full set; filtering is applied client-side by the caller).
func (c *Client) ListEnclaves(ctx context.Context) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/admin/enclaves", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "enclaves")
}

// GetEnclave returns one enclave's full record (GET /api/v1/admin/enclaves/{id}).
func (c *Client) GetEnclave(ctx context.Context, id string) (map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/admin/enclaves/"+url.PathEscape(id), &raw); err != nil {
		return nil, err
	}
	return unwrapObject(raw, "enclave")
}

// ListEnclaveApps returns the deployments placed on an enclave, newest first
// within each app (platform managers only).
func (c *Client) ListEnclaveApps(ctx context.Context, id string) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/admin/enclaves/"+url.PathEscape(id)+"/apps", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "apps")
}

// StageDataKey stages an OS release's measurements on the enclave's manager
// /data key. release is a release tag, or the release's https URL.
func (c *Client) StageDataKey(ctx context.Context, id, release string) (map[string]interface{}, error) {
	body := map[string]string{}
	setOSRelease(body, release)
	var out map[string]interface{}
	err := c.do(ctx, http.MethodPost, "/api/v1/admin/enclaves/"+url.PathEscape(id)+"/data-key/stage", body, &out)
	return out, err
}

// DataKeyPending lists the profiles staged on the enclave's manager /data key.
func (c *Client) DataKeyPending(ctx context.Context, id string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, "/api/v1/admin/enclaves/"+url.PathEscape(id)+"/data-key/pending", &out)
	return out, err
}

// PromoteDataKey promotes a staged profile on the enclave's manager /data key.
// The admin bearer authorises the route; the operation-bound step-up token is
// what the control plane forwards to the vaults. The answer is 200 whatever the
// vaults said, so the caller counts their successes.
func (c *Client) PromoteDataKey(ctx context.Context, id string, pendingID uint32, stepUp string) (map[string]interface{}, error) {
	body, err := json.Marshal(map[string]uint32{"pending_id": pendingID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/admin/enclaves/"+url.PathEscape(id)+"/data-key/promote", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.authorize(req)
	req.Header.Set("X-Privasys-Step-Up", stepUp)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err := statusError(resp.StatusCode, data); err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}
