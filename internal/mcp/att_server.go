// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"fmt"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/ratls"
)

// attServerURL is the attestation server every app call verifies the
// enclave's quote with.
const attServerURL = "https://as.privasys.org/verify"

// appCallTarget is the hostname of the app's running deployment and the pin
// its serving leaf must match (ratls.PinFor), both from the same deployment.
func appCallTarget(ctx context.Context, d Deps, app map[string]interface{}, appID string) (string, *ratls.AppPin, error) {
	dep, ver, err := d.Client.RunningDeploymentAndVersion(ctx, appID)
	if err != nil {
		return "", nil, fmt.Errorf("%w; the app must be deployed and running to call it", err)
	}
	host, _ := dep["hostname"].(string)
	if host == "" {
		return "", nil, fmt.Errorf("the app's running deployment has no hostname")
	}
	pin, err := ratls.PinFor(app, dep, ver)
	if err != nil {
		return "", nil, ratls.Refused("the app's enclave cannot be pinned, so nothing was sent: %w", err)
	}
	return host, pin, nil
}

// attServerToken is a token for the attestation server, or "" (the call is
// then refused before anything is sent).
func attServerToken(ctx context.Context, d Deps) string {
	tok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
	return tok
}
