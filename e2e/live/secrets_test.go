// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package live

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/Privasys/cli/e2e/mockwallet"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// devVaults resolves the vault endpoints, MRENCLAVE and threshold for the live
// secrets tests, defaulting to the CLI's production constellation and allowing
// the dev grant vaults to be supplied via PRIVASYS_E2E_VAULT* env vars.
func devVaults() (endpoints []string, mrenclave string, threshold int) {
	endpoints = secrets.DefaultEndpoints
	mrenclave = secrets.DefaultMRENCLAVE
	threshold = 2
	if v := os.Getenv("PRIVASYS_E2E_VAULTS"); v != "" {
		endpoints = strings.Split(v, ",")
	}
	if v := os.Getenv("PRIVASYS_E2E_VAULT_MRENCLAVE"); v != "" {
		mrenclave = v
	}
	if v := os.Getenv("PRIVASYS_E2E_VAULT_THRESHOLD"); v != "" {
		threshold, _ = strconv.Atoi(v)
	}
	return
}

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

	endpoints, mrenclave, threshold := devVaults()

	name := "e2e-secret-" + randHex(4)
	res, err := secrets.Create(ctx, secrets.CreateParams{
		Issuer: issuer, Bearer: tok, Sub: sub,
		Handle:     "users/" + sub + "/" + name,
		Secret:     []byte("e2e-secret-value-" + name),
		Exportable: true,
		Endpoints:  endpoints,
		Threshold:  threshold,
		MRENCLAVE:  mrenclave,
		AttServer:  "https://as.privasys.org/verify",
		AttToken:   attTok,
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

// TestLiveSecretsExport proves the owner-export path end to end: a cold user
// (fresh software wallet) signs in, creates an exportable secret, then exports
// it back — gated by a fresh, operation-bound WebAuthn step-up the same wallet
// approves. The reconstructed key must equal what was created.
//
// Needs the Go RA-TLS fork (`-tags ratls`) AND a vault constellation + IdP that
// carry the operation-bound export step-up (the vault's handle_export binding +
// the IdP's operation:"export" grant). Point it at the dev grant vaults via
// PRIVASYS_E2E_VAULTS / PRIVASYS_E2E_VAULT_MRENCLAVE.
func TestLiveSecretsExport(t *testing.T) {
	issuer := skipUnlessLive(t)
	// In-memory keychain + throwaway config so the harness's real session is
	// untouched; the wallet we keep is the one that can sign the step-up.
	keyring.MockInit()
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Cold onboard a fresh user with a software wallet (real device grant).
	wallet := mockwallet.New()
	dr, verifier, err := auth.BeginDevice(ctx, issuer, auth.DefaultScope, "privasys-cli-e2e")
	if err != nil {
		t.Fatalf("BeginDevice: %v", err)
	}
	if err := wallet.ApproveDevice(ctx, issuer, dr.UserCode); err != nil {
		t.Fatalf("mock wallet approve: %v", err)
	}
	tr, err := auth.PollUntil(ctx, issuer, dr.DeviceCode, verifier, dr.Interval, dr.ExpiresIn)
	if err != nil {
		t.Fatalf("PollUntil: %v", err)
	}
	if err := auth.SaveUserCredential(issuer, tr); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	tok, err := auth.AccessToken(ctx, issuer)
	if err != nil {
		t.Fatalf("access token: %v", err)
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
	endpoints, mrenclave, threshold := devVaults()

	// 2. Create an exportable secret as that user.
	name := "e2e-export-" + randHex(4)
	handle := "users/" + sub + "/" + name
	want := []byte("e2e-export-value-" + name)
	if _, err := secrets.Create(ctx, secrets.CreateParams{
		Issuer: issuer, Bearer: tok, Sub: sub, Handle: handle,
		Secret: want, Exportable: true, Endpoints: endpoints, Threshold: threshold,
		MRENCLAVE: mrenclave, AttServer: "https://as.privasys.org/verify", AttToken: attTok,
	}); err != nil {
		t.Fatalf("secrets create: %v", err)
	}

	// 3. Export it back, with the wallet signing the operation-bound step-up.
	got, eres, err := secrets.Export(ctx, secrets.ExportParams{
		Issuer: issuer, Bearer: tok, Sub: sub, Handle: handle,
		Endpoints: endpoints, Threshold: threshold, MRENCLAVE: mrenclave,
		AttServer: "https://as.privasys.org/verify", AttToken: attTok,
		Assert: wallet.AssertStepUp,
	})
	if err != nil {
		t.Fatalf("secrets export: %v", err)
	}
	t.Logf("exported %s: %d/%d vaults, %s", eres.Handle, eres.Retrieved, eres.Total, eres.Fingerprint)
	if !bytes.Equal(got, want) {
		t.Fatalf("exported key does not match what was created")
	}
}
