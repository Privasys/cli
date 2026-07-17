// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/url"
)

// First-class volumes: encrypted storage owned independently of apps. A
// volume is created at first deploy, keeps billing per GB-hour (attached or
// not) until deleted, and survives app deletion by default.

// ListVolumes returns the caller's volumes.
func (c *Client) ListVolumes(ctx context.Context) ([]map[string]interface{}, error) {
	var out struct {
		Volumes []map[string]interface{} `json:"volumes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/volumes", nil, &out); err != nil {
		return nil, err
	}
	return out.Volumes, nil
}

// GetVolume returns one volume with live used/free space when its host answers.
func (c *Client) GetVolume(ctx context.Context, id string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodGet, "/api/v1/volumes/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ResizeVolume grows a volume to sizeGB (grow-only).
func (c *Client) ResizeVolume(ctx context.Context, id string, sizeGB int) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/volumes/"+url.PathEscape(id)+"/resize",
		map[string]int{"size_gb": sizeGB}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteVolume deletes a volume: the LV is removed from its host and billing
// stops. Refused while the volume is attached to a running app.
func (c *Client) DeleteVolume(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/volumes/"+url.PathEscape(id), nil, nil)
}
