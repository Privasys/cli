// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is a thin typed client for the public Privasys platform API
// (the management service). It speaks only the documented public surface.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the platform API with a bearer access token.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New creates a client for the given API base URL and access token.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		// 120s matches the server's deploy/lifecycle route timeout: some
		// operations (dedicated instance stop/start/delete) drive the
		// cloud-ops agent synchronously through gcloud, which takes ~40s.
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// getJSON performs an authenticated GET and decodes the JSON body.
func (c *Client) getJSON(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("not authorized (%d) — check your login and account access", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// ListApps returns the caller's apps as generic records (the CLI renders a
// stable subset of columns and can emit the full objects as JSON/YAML, so it
// does not pin the full server schema).
func (c *Client) ListApps(ctx context.Context) ([]map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps", &raw); err != nil {
		return nil, err
	}
	return unwrapList(raw, "apps")
}

// GetApp returns a single app's full record.
func (c *Client) GetApp(ctx context.Context, id string) (map[string]interface{}, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/apps/"+id, &raw); err != nil {
		return nil, err
	}
	return unwrapObject(raw, "app")
}

// unwrapList accepts either a bare JSON array or an object wrapping the array
// under a known key (e.g. {"apps":[...]} or {"data":[...]}).
func unwrapList(raw json.RawMessage, key string) ([]map[string]interface{}, error) {
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("unexpected list response")
	}
	for _, k := range []string{key, "data", "items", "results"} {
		if v, ok := obj[k]; ok {
			if err := json.Unmarshal(v, &arr); err == nil {
				return arr, nil
			}
		}
	}
	return nil, fmt.Errorf("could not find a list in the response")
}

func unwrapObject(raw json.RawMessage, key string) (map[string]interface{}, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("unexpected object response")
	}
	// Some endpoints wrap the entity (e.g. {"app":{...}}); unwrap when the
	// wrapper is the sole, object-valued key.
	if len(obj) == 1 {
		if inner, ok := obj[key].(map[string]interface{}); ok {
			return inner, nil
		}
	}
	return obj, nil
}
