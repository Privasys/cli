// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package live

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// L3b key-lifecycle E2E: prove the data-protection guarantees on a real
// deployed storage app — rotate-key (online re-key, the DEK still reconstructs)
// and owner-approved upgrade (a new code measurement is GATED until the owner
// promotes it, and the data key survives). Verified via owner export of the DEK,
// so these don't depend on the app container serving HTTP ("active").
//
// Needs the Go RA-TLS fork (`-tags ratls`), the AMBIENT owner session, and a TDX
// container enclave (target m1-dev with PRIVASYS_E2E_ENCLAVE). Env mirrors
// TestLiveAppExportKey.

// deployStorageApp creates + deploys a vault-backed storage container app and
// returns its id, version id, and the resolved enclave id (from
// PRIVASYS_E2E_ENCLAVE or the only compatible one). Registers teardown.
func deployStorageApp(t *testing.T, ctx context.Context, client *api.Client, enclaveID, image, name string) (appID, vid, enc string) {
	t.Helper()
	app, err := client.CreateApp(ctx, map[string]interface{}{
		"name": name, "source_type": "package", "app_type": "container",
		"container_image": image, "container_storage": true, "key_provider": "enclave_generated",
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	appID, _ = app["id"].(string)
	t.Cleanup(func() {
		if derr := client.DeleteApp(context.Background(), appID); derr != nil {
			t.Logf("teardown: delete app %s: %v", appID, derr)
		} else {
			t.Logf("teardown: deleted app %s", appID)
		}
	})
	if _, err := client.UpdateStoreListing(ctx, appID, map[string]interface{}{
		"store_description": "Ephemeral E2E key-lifecycle storage app.",
		"store_category":    "Developer Tools",
	}); err != nil {
		t.Fatalf("set store listing: %v", err)
	}
	if _, err := client.CreateVersion(ctx, appID, map[string]string{"image": image}); err != nil {
		t.Fatalf("create version: %v", err)
	}
	vs, err := client.ListVersions(ctx, appID)
	if err != nil || len(vs) == 0 {
		t.Fatalf("list versions: %v (n=%d)", err, len(vs))
	}
	vid, _ = vs[len(vs)-1]["id"].(string)
	enc = enclaveID
	if enc == "" {
		encs, eerr := client.CompatibleEnclaves(ctx, appID)
		if eerr != nil || len(encs) == 0 {
			t.Fatalf("compatible enclaves: %v (n=%d)", eerr, len(encs))
		}
		enc, _ = encs[0]["id"].(string)
	}
	if _, err := client.DeployVersion(ctx, appID, vid, enc, ""); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return appID, vid, enc
}

// exportAppDEK exports the app's DEK as the owner (refreshing the bearer). Skips
// the test if the policy requires a WebAuthn step-up.
func exportAppDEK(t *testing.T, ctx context.Context, client *api.Client, issuer, sub, appID string) []byte {
	t.Helper()
	tok, err := auth.AccessToken(ctx, issuer)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	client.Token = tok
	target, err := client.GetVaultExportTarget(ctx, appID)
	if err != nil {
		t.Fatalf("export target: %v", err)
	}
	if target.RequireStepUp {
		t.Skip("app DEK requires WebAuthn step-up; needs the wallet relay")
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, issuer, "attestation-server")
	key, _, err := secrets.Export(ctx, secrets.ExportParams{
		Issuer: issuer, Bearer: tok, Sub: sub, Handle: target.Handle,
		Endpoints: target.Endpoints, Threshold: target.Threshold,
		MRENCLAVE: target.MRENCLAVE, AttServer: target.AttestationServer, AttToken: attTok,
		GenerationSize: secrets.AppDEKGenerationSize,
	})
	if err != nil {
		t.Fatalf("export DEK: %v", err)
	}
	return key
}

// pollExportAppDEK polls exportAppDEK until the DEK is provisioned (created
// during volume setup, shortly after deploy starts).
func pollExportAppDEK(t *testing.T, ctx context.Context, client *api.Client, issuer, sub, appID string, within time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if tok, terr := auth.AccessToken(ctx, issuer); terr == nil && tok != "" {
			client.Token = tok
		}
		target, terr := client.GetVaultExportTarget(ctx, appID)
		if terr == nil && target.RequireStepUp {
			t.Skip("app DEK requires WebAuthn step-up; needs the wallet relay")
		}
		if terr == nil {
			attTok, _ := auth.AccessTokenForAudience(ctx, issuer, "attestation-server")
			tok, _ := auth.AccessToken(ctx, issuer)
			key, _, eerr := secrets.Export(ctx, secrets.ExportParams{
				Issuer: issuer, Bearer: tok, Sub: sub, Handle: target.Handle,
				Endpoints: target.Endpoints, Threshold: target.Threshold,
				MRENCLAVE: target.MRENCLAVE, AttServer: target.AttestationServer, AttToken: attTok,
				GenerationSize: secrets.AppDEKGenerationSize,
			})
			if eerr == nil {
				return key
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("DEK never became exportable")
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled: %v", ctx.Err())
		case <-time.After(10 * time.Second):
		}
	}
}

// TestLiveRotateKey proves online key rotation: the volume's vault-held key is
// rotated (re-keyed, new generation) without losing the data — the DEK still
// reconstructs afterwards, and is a different value (a real rotation).
func TestLiveRotateKey(t *testing.T) {
	issuer := skipUnlessLive(t)
	endpoint := os.Getenv("PRIVASYS_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PRIVASYS_E2E_ENDPOINT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
	defer cancel()
	tok, err := auth.AccessToken(ctx, issuer)
	if err != nil {
		t.Skipf("no authorized session: %v", err)
	}
	claims, _ := auth.Claims(tok)
	sub, _ := claims["sub"].(string)
	client := api.New(endpoint, tok)

	enc := os.Getenv("PRIVASYS_E2E_ENCLAVE")
	image := envOr("PRIVASYS_E2E_IMAGE", "ghcr.io/privasys/container-app-example:v1.0.1")
	appID, vid, enc := deployStorageApp(t, ctx, client, enc, image, "e2e-rot-"+randHex(4))

	before := pollExportAppDEK(t, ctx, client, issuer, sub, appID, 6*time.Minute)
	t.Logf("DEK before rotation: %d bytes", len(before))

	if _, err := client.RotateKey(ctx, appID, vid, enc); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	t.Logf("rotate-key requested; re-exporting")

	// The handle advances to the new generation; export the rotated DEK.
	var after []byte
	deadline := time.Now().Add(3 * time.Minute)
	for {
		after = exportAppDEK(t, ctx, client, issuer, sub, appID)
		if !bytes.Equal(after, before) {
			break // rotation took effect (new key value)
		}
		if time.Now().After(deadline) {
			t.Fatal("DEK value unchanged after rotate-key (rotation did not take effect)")
		}
		time.Sleep(8 * time.Second)
	}
	if len(after) == 0 {
		t.Fatal("post-rotation DEK is empty")
	}
	t.Logf("rotated OK: DEK changed (%d bytes), still reconstructs from the constellation", len(after))
}

// TestLiveUpgradeSurvival proves the owner-approved upgrade gate: a new code
// measurement is staged + GATED (pending) until the owner promotes it, and the
// data key survives the upgrade (same DEK before and after).
func TestLiveUpgradeSurvival(t *testing.T) {
	issuer := skipUnlessLive(t)
	endpoint := os.Getenv("PRIVASYS_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PRIVASYS_E2E_ENDPOINT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
	defer cancel()
	tok, err := auth.AccessToken(ctx, issuer)
	if err != nil {
		t.Skipf("no authorized session: %v", err)
	}
	claims, _ := auth.Claims(tok)
	sub, _ := claims["sub"].(string)
	client := api.New(endpoint, tok)

	enc := os.Getenv("PRIVASYS_E2E_ENCLAVE")
	image := envOr("PRIVASYS_E2E_IMAGE", "ghcr.io/privasys/container-app-example:v1.0.1")
	// A DIFFERENT image digest = a new measurement to gate on.
	image2 := envOr("PRIVASYS_E2E_IMAGE2", "ghcr.io/privasys/container-app-example:v1.0.0")

	appID, _, enc := deployStorageApp(t, ctx, client, enc, image, "e2e-upg-"+randHex(4))

	before := pollExportAppDEK(t, ctx, client, issuer, sub, appID, 6*time.Minute)
	t.Logf("DEK before upgrade: %d bytes", len(before))

	// New version with a different measurement.
	if _, err := client.CreateVersion(ctx, appID, map[string]string{"image": image2}); err != nil {
		t.Fatalf("create upgrade version: %v", err)
	}
	vs, err := client.ListVersions(ctx, appID)
	if err != nil || len(vs) < 2 {
		t.Fatalf("list versions: %v (n=%d)", err, len(vs))
	}
	v2, _ := vs[len(vs)-1]["id"].(string)

	// Stage the new measurement: the data key is GATED until the owner promotes.
	staged, err := client.StageProfile(ctx, appID, v2, enc)
	if err != nil {
		t.Fatalf("stage profile: %v", err)
	}
	t.Logf("staged new measurement: %v", staged)

	pend, err := client.ListPending(ctx, appID, v2)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	// The fan-out shape is {vaults: [{ok, vault, pending: [{id, profile, ...}]}]}.
	pendingID := -1
	vaults, _ := pend["vaults"].([]interface{})
	for _, v := range vaults {
		vm, _ := v.(map[string]interface{})
		pl, _ := vm["pending"].([]interface{})
		if len(pl) == 0 {
			continue
		}
		first, _ := pl[0].(map[string]interface{})
		if idv, ok := first["id"].(float64); ok {
			pendingID = int(idv)
			break
		}
	}
	if pendingID < 0 {
		t.Fatalf("no pending profile staged — the upgrade gate did not engage: %v", pend)
	}
	t.Logf("upgrade GATED: pending profile #%d awaiting owner approval", pendingID)

	// Owner promotes (authorizes the new measurement to read the data key).
	if _, err := client.PromoteProfile(ctx, appID, v2, pendingID); err != nil {
		t.Fatalf("promote (owner approval): %v", err)
	}
	t.Logf("owner promoted the new measurement")

	// The data key survives the upgrade.
	after := exportAppDEK(t, ctx, client, issuer, sub, appID)
	if !bytes.Equal(after, before) {
		t.Fatalf("data key did NOT survive the upgrade: before %d bytes, after %d bytes (differ)", len(before), len(after))
	}
	t.Logf("upgrade survival OK: same %d-byte DEK after owner-approved promote", len(after))
}
