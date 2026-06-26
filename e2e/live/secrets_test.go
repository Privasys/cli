// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package live

import (
	"context"
	"testing"
	"time"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// TestLiveSecretsCreate exercises `secrets create` end to end against the real
// IdP and the production vault constellation: the CLI (as the signed-in user)
// gets a holder-of-key key-creation grant from the IdP, then creates a
// user-owned, Shamir-split secret across the vaults over mutual RA-TLS.
//
// Needs the Go RA-TLS fork (`-tags ratls`) and an ambient authorized session.
// Set PRIVASYS_E2E=1. Creates a small key under users/<your-sub>/.
func TestLiveSecretsCreate(t *testing.T) {
	issuer := skipUnlessLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tok, err := auth.AccessToken(ctx, issuer)
	if err != nil {
		t.Skipf("no authorized session: %v", err)
	}
	claims, err := auth.Claims(tok)
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Fatal("no sub in session")
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, issuer, "attestation-server")

	name := "e2e-secret-" + randHex(4)
	res, err := secrets.Create(ctx, secrets.CreateParams{
		Issuer: issuer, Bearer: tok, Sub: sub,
		Handle:     "users/" + sub + "/" + name,
		Secret:     []byte("e2e-secret-value-" + name),
		Exportable: true,
		Endpoints: []string{
			"141.94.219.130:8443", "141.94.219.130:8444",
			"198.244.201.58:8443", "198.244.201.58:8444",
		},
		Threshold: 2,
		MRENCLAVE: "7f45fa40256be86a6faf9b2b03ffa69984e8b9d8e4e016614d81a31221cbfcb2",
		AttServer: "https://as.privasys.org/verify",
		AttToken:  attTok,
	})
	if err != nil {
		t.Fatalf("secrets create: %v", err)
	}
	t.Logf("created secret %s: %d/%d vaults accepted (threshold %d), exportable=%v",
		res.Handle, res.Created, res.Total, res.Threshold, res.Exportable)
	if res.Created < res.Threshold {
		t.Fatalf("only %d/%d vaults accepted (need %d)", res.Created, res.Total, res.Threshold)
	}
}
