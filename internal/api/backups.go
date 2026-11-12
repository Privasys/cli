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

// SetBackupPolicy changes the app's backup schedule: interval hourly|every-6h|daily|off,
// retention standard (proportionate is its alias) or minimal, redundancy region
// or zones. An empty value keeps the current one. Changing the redundancy of an
// app that has backups moves them, which needs the app running.
func (c *Client) SetBackupPolicy(ctx context.Context, appID, interval, retention, redundancy string) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	for k, v := range map[string]string{"interval": interval, "retention": retention, "redundancy": redundancy} {
		if v != "" {
			body[k] = v
		}
	}
	var out map[string]interface{}
	err := c.do(ctx, http.MethodPut, "/api/v1/apps/"+url.PathEscape(appID)+"/backups/policy", body, &out)
	return out, err
}

// ListBackupSets lists the owner's backup repositories, one per app, the
// backups of deleted apps included (they are kept, and billed, like volumes).
func (c *Client) ListBackupSets(ctx context.Context) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, "/api/v1/backups", &out)
	return out, err
}

// GetBackupSet reads one app's restore points, the app deleted or not.
func (c *Client) GetBackupSet(ctx context.Context, appID string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, "/api/v1/backups/"+url.PathEscape(appID), &out)
	return out, err
}

// DeleteBackupSet deletes a deleted app's backups and stops their billing. The
// platform refuses while the app exists: its backups go with it (DeleteAppWith).
func (c *Client) DeleteBackupSet(ctx context.Context, appID string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/backups/"+url.PathEscape(appID), nil, nil)
}

// backupAccessPath is a live app's access route, or that of any app's kept
// backups (the app deleted or not).
func backupAccessPath(appID string, live bool) string {
	if live {
		return "/api/v1/apps/" + url.PathEscape(appID) + "/backups/access"
	}
	return "/api/v1/backups/" + url.PathEscape(appID) + "/access"
}

// GetBackupAccess says whether the app's backups have a read-only access key,
// and where the repository is. It never carries the secret.
func (c *Client) GetBackupAccess(ctx context.Context, appID string, live bool) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.getJSON(ctx, backupAccessPath(appID, live), &out)
	return out, err
}

// CreateBackupAccess issues a read-only S3 key limited to the app's own
// repository, for last-resort restores with stock kopia. The reply carries
// secret_access_key, once: the platform does not keep it. A new key replaces
// the previous one.
func (c *Client) CreateBackupAccess(ctx context.Context, appID string, live bool) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := c.do(ctx, http.MethodPost, backupAccessPath(appID, live), map[string]interface{}{}, &out)
	return out, err
}

// RevokeBackupAccess deletes the app's read-only access key.
func (c *Client) RevokeBackupAccess(ctx context.Context, appID string, live bool) error {
	return c.do(ctx, http.MethodDelete, backupAccessPath(appID, live), nil, nil)
}
