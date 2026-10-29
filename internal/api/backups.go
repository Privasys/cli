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

// GetBackupPolicy reads the app's backup schedule.
func (c *Client) GetBackupPolicy(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, "/api/v1/apps/"+url.PathEscape(appID)+"/backups/policy", &out)
	return out, err
}

// SetBackupPolicy sets the app's backup schedule: interval hourly|every-6h|daily|off,
// retention standard|proportionate|minimal.
func (c *Client) SetBackupPolicy(ctx context.Context, appID, interval, retention string) (map[string]interface{}, error) {
	body := map[string]interface{}{"interval": interval}
	if retention != "" {
		body["retention"] = retention
	}
	var out map[string]interface{}
	err := c.do(ctx, http.MethodPut, "/api/v1/apps/"+url.PathEscape(appID)+"/backups/policy", body, &out)
	return out, err
}
