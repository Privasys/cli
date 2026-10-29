// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/url"
)

// StartBackup asks the enclave running the app to back its volume up now.
func (c *Client) StartBackup(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+url.PathEscape(appID)+"/backups", map[string]interface{}{}, &out)
	return out, err
}

// ListBackups lists the app's restore points.
func (c *Client) ListBackups(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, "/api/v1/apps/"+url.PathEscape(appID)+"/backups", &out)
	return out, err
}

// BackupStatus reports the app's latest backup job.
func (c *Client) BackupStatus(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, "/api/v1/apps/"+url.PathEscape(appID)+"/backups/status", &out)
	return out, err
}
