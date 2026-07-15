// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
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
