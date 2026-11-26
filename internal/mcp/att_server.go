// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"

	"github.com/Privasys/cli/internal/auth"
)

// attServerURL is the attestation server every app call verifies the
// enclave's quote with.
const attServerURL = "https://as.privasys.org/verify"

// attServerToken is a token for the attestation server, or "" (the call is
// then refused before anything is sent).
func attServerToken(ctx context.Context, d Deps) string {
	tok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
	return tok
}
