// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package live

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// TestLiveAppExportKey proves the owner can export a DEPLOYED app's data key:
// create a vault-backed storage container app, deploy it (the app TEE creates
// its DEK in the vault under the owner-export policy), then export that key as
// the owner directly from the vaults over RA-TLS and reconstruct it.
//
// Uses the AMBIENT authorized session (the app owner). Needs the Go RA-TLS fork
// (`-tags ratls`). Env:
//
//	PRIVASYS_E2E=1
//	PRIVASYS_E2E_ENDPOINT   management-service base URL (dev: https://api-test.developer.privasys.org)
//	PRIVASYS_E2E_IMAGE      optional container image
//	PRIVASYS_E2E_ENCLAVE    optional enclave id (default: the only compatible one)
func TestLiveAppExportKey(t *testing.T) {
	issuer := skipUnlessLive(t)
	endpoint := os.Getenv("PRIVASYS_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PRIVASYS_E2E_ENDPOINT to the management-service base URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
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
	client := api.New(endpoint, tok)

	image := envOr("PRIVASYS_E2E_IMAGE", "ghcr.io/privasys/container-app-example:v1.0.0")
	name := "e2e-dek-" + randHex(4)

	// 1. Create a vault-backed storage container app (the DEK is owner-exportable).
	app, err := client.CreateApp(ctx, map[string]interface{}{
		"name": name, "source_type": "package", "app_type": "container",
		"container_image": image, "container_storage": true, "key_provider": "enclave_generated",
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	appID, _ := app["id"].(string)
	t.Logf("created storage app %s (%s)", name, appID)
	t.Cleanup(func() {
		if err := client.DeleteApp(context.Background(), appID); err != nil {
			t.Logf("teardown: delete app %s: %v", appID, err)
		} else {
			t.Logf("teardown: deleted app %s", appID)
		}
	})

	// 2. Listing (required before deploy), version, deploy.
	if _, err := client.UpdateStoreListing(ctx, appID, map[string]interface{}{
		"store_description": "Ephemeral E2E storage app for the app-DEK export harness.",
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
	vid, _ := vs[len(vs)-1]["id"].(string)

	enclaveID := os.Getenv("PRIVASYS_E2E_ENCLAVE")
	if enclaveID == "" {
		encs, err := client.CompatibleEnclaves(ctx, appID)
		if err != nil || len(encs) == 0 {
			t.Fatalf("compatible enclaves: %v (n=%d)", err, len(encs))
		}
		enclaveID, _ = encs[0]["id"].(string)
	}
	dep, err := client.DeployVersion(ctx, appID, vid, enclaveID)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	depID, _ := dep["id"].(string)
	t.Logf("deployment %s started; polling for the DEK to become exportable", depID)

	// 3. Export the DEK as the owner. The DEK is created during encrypted-volume
	// setup (well before the container is "active"), so we poll the export rather
	// than waiting for "active" — which depends on the app image's health check,
	// not on the data key. Refresh the bearer each attempt (long deploys outlive
	// the token TTL).
	deadline := time.Now().Add(6 * time.Minute)
	var key []byte
	var res *secrets.ExportResult
	var lastErr error
	for {
		if fresh, ferr := auth.AccessToken(ctx, issuer); ferr == nil && fresh != "" {
			tok = fresh
			client.Token = tok
		}
		target, terr := client.GetVaultExportTarget(ctx, appID)
		if terr != nil {
			lastErr = terr
		} else if target.RequireStepUp {
			t.Skip("app DEK requires WebAuthn step-up; needs the wallet relay (out of scope for an ambient-session test)")
		} else {
			attTok, _ := auth.AccessTokenForAudience(ctx, issuer, "attestation-server")
			k, r, eerr := secrets.Export(ctx, secrets.ExportParams{
				Issuer: issuer, Bearer: tok, Sub: sub, Handle: target.Handle,
				Endpoints: target.Endpoints, Threshold: target.Threshold,
				MRENCLAVE: target.MRENCLAVE, AttServer: target.AttestationServer, AttToken: attTok,
				RequireStepUp:  target.RequireStepUp,
				GenerationSize: secrets.AppDEKGenerationSize,
			})
			if eerr == nil {
				key, res = k, r
				break
			}
			lastErr = eerr
		}
		if time.Now().After(deadline) {
			t.Fatalf("DEK never became exportable: %v", lastErr)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled: %v", ctx.Err())
		case <-time.After(10 * time.Second):
		}
	}
	if len(key) == 0 {
		t.Fatal("exported an empty key")
	}
	t.Logf("exported app DEK %s: %d bytes, %d/%d vaults, %s",
		res.Handle, len(key), res.Retrieved, res.Total, res.Fingerprint)
}
