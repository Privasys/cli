// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package live holds the L3 end-to-end harness that runs against real
// infrastructure. Every test here is gated on PRIVASYS_E2E=1 so it never runs
// in the normal unit-test/CI path.
//
// Targets (see .operations/infrastructure.md):
//   - Auth:  the prod IdP https://privasys.id (device grant + FIDO2).
//   - Apps:  the dev management-service api-test.developer.privasys.org, which
//     manages the dev enclaves (SGX Paris :8446 for wasm, m1-dev for
//     containers) and validates privasys-platform tokens from the IdP.
package live

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Privasys/cli/e2e/mockwallet"
	"github.com/Privasys/cli/internal/auth"
)

func skipUnlessLive(t *testing.T) string {
	t.Helper()
	if os.Getenv("PRIVASYS_E2E") == "" {
		t.Skip("set PRIVASYS_E2E=1 to run live E2E against real infrastructure")
	}
	issuer := os.Getenv("PRIVASYS_E2E_IDP")
	if issuer == "" {
		issuer = "https://privasys.id"
	}
	return issuer
}

// TestLiveDeviceOnboarding proves the cold-start auth loop end to end against
// the real IdP: the CLI starts a device authorization, the software wallet
// approves it (real FIDO2 registration), and the CLI obtains a token — no human
// and no phone. This is the auth half of the L3 onboarding flow.
func TestLiveDeviceOnboarding(t *testing.T) {
	issuer := skipUnlessLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dr, verifier, err := auth.BeginDevice(ctx, issuer, auth.DefaultScope, "privasys-cli-e2e")
	if err != nil {
		t.Fatalf("BeginDevice: %v", err)
	}
	t.Logf("device authorization: user_code=%s verification_uri=%s", dr.UserCode, dr.VerificationURI)

	// The software wallet plays the human + phone: it registers a fresh
	// credential bound to the device session, which approves it.
	if err := mockwallet.New().ApproveDevice(ctx, issuer, dr.UserCode); err != nil {
		t.Fatalf("mock wallet approve: %v", err)
	}

	tr, err := auth.PollUntil(ctx, issuer, dr.DeviceCode, verifier, dr.Interval, dr.ExpiresIn)
	if err != nil {
		t.Fatalf("PollUntil after approval: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("no access token after approval")
	}
	claims, _ := auth.Claims(tr.AccessToken)
	t.Logf("authenticated: sub=%v aud=%v", claims["sub"], claims["aud"])
}
