// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package live

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/Privasys/cli/e2e/mockwallet"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/ratls"
)

// TestLiveAttest proves the RA-TLS data plane end to end: authenticate as a cold
// user (real device grant + software wallet), mint an attestation-server token,
// then connect to a real enclave over RA-TLS, challenge it with a fresh nonce,
// and verify its hardware quote against the attestation server.
//
// Runs against live infrastructure.
// Set PRIVASYS_E2E=1 and PRIVASYS_E2E_HOST=<enclave gateway FQDN>, e.g.
// container-app-lightpanda.apps.privasys.org.
func TestLiveAttest(t *testing.T) {
	issuer := skipUnlessLive(t)
	host := os.Getenv("PRIVASYS_E2E_HOST")
	if host == "" {
		t.Skip("set PRIVASYS_E2E_HOST to an enclave gateway FQDN to run the live attest test")
	}
	// In-memory keychain + a throwaway config dir, so the harness's own session
	// never touches the developer's real credentials.
	keyring.MockInit()
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dr, verifier, err := auth.BeginDevice(ctx, issuer, auth.DefaultScope, "privasys-cli-e2e")
	if err != nil {
		t.Fatalf("BeginDevice: %v", err)
	}
	if err := mockwallet.New().ApproveDevice(ctx, issuer, dr.UserCode); err != nil {
		t.Fatalf("mock wallet approve: %v", err)
	}
	tr, err := auth.PollUntil(ctx, issuer, dr.DeviceCode, verifier, dr.Interval, dr.ExpiresIn)
	if err != nil {
		t.Fatalf("PollUntil: %v", err)
	}
	if err := auth.SaveUserCredential(issuer, tr); err != nil {
		t.Fatalf("save credential: %v", err)
	}

	attTok, err := auth.AccessTokenForAudience(ctx, issuer, "attestation-server")
	if err != nil {
		t.Fatalf("mint attestation-server token: %v", err)
	}

	res, err := ratls.Verify(ctx, ratls.Params{
		Host:         host,
		ServerName:   host,
		Challenge:    ratls.NewNonce(),
		AttServerURL: "https://as.privasys.org/verify",
		AttServerTok: attTok,
	})
	if err != nil {
		t.Fatalf("attest %s: %v", host, err)
	}
	t.Logf("attest %s: verified=%v challenged=%v", host, res.Verified, res.Challenged)
	if !res.Verified {
		t.Fatalf("attestation NOT verified for %s", host)
	}
}
