// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/url"
)

// CreateAppKeyGrant asks the platform to author the policy of an app's
// owner-held storage key (key_provider byok) for the given version on the given
// enclave, and to mint a creation grant bound to this client's holder-of-key
// leaf (cnf). The response has the same shape as a registry-credential grant.
func (c *Client) CreateAppKeyGrant(ctx context.Context, appID, cnf, enclaveID, versionID string) (*RegistrySecretResponse, error) {
	body := map[string]interface{}{"cnf_x5t_s256": cnf, "version_id": versionID}
	if enclaveID != "" {
		body["enclave_id"] = enclaveID
	}
	var out RegistrySecretResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/apps/"+url.PathEscape(appID)+"/key", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
