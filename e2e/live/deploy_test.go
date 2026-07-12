// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package live

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/ratls"
)

// TestLiveDeploy closes the L3 happy path: create a confidential app, deploy it
// to a real enclave, and verify it by attestation — the control plane plus the
// data-plane verify, against real infrastructure.
//
// It uses the AMBIENT authorized session (a real `auth login` or
// PRIVASYS_SERVICE_KEY): creating + deploying needs an account, unlike the
// cold-auth onboarding/attest tests. Deliberately a NON-STORAGE container so it
// never touches the (in-flight) vault key-creation path.
//
// Needs the Go RA-TLS fork (`-tags ratls`). Env:
//
//	PRIVASYS_E2E=1
//	PRIVASYS_E2E_ENDPOINT   management-service base URL (e.g. https://api-test.developer.privasys.org)
//	PRIVASYS_E2E_IMAGE      optional container image (default: container-app-example:v1.0.1)
//	PRIVASYS_E2E_ENCLAVE    optional enclave id (default: the only compatible one)
func TestLiveDeploy(t *testing.T) {
	issuer := skipUnlessLive(t)
	endpoint := os.Getenv("PRIVASYS_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PRIVASYS_E2E_ENDPOINT to the management-service base URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	tok, err := auth.AccessToken(ctx, issuer)
	if err != nil {
		t.Skipf("no authorized session (run `privasys auth login` or set PRIVASYS_SERVICE_KEY): %v", err)
	}
	client := api.New(endpoint, tok)

	image := envOr("PRIVASYS_E2E_IMAGE", "ghcr.io/privasys/container-app-example:v1.0.1")
	name := "e2e-l3-" + randHex(4)

	// 1. Create a non-storage container app (no vault key).
	app, err := client.CreateApp(ctx, map[string]interface{}{
		"name": name, "source_type": "package", "app_type": "container",
		"container_image": image,
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	appID, _ := app["id"].(string)
	t.Logf("created app %s (%s)", name, appID)
	t.Cleanup(func() {
		if err := client.DeleteApp(context.Background(), appID); err != nil {
			t.Logf("teardown: delete app %s: %v", appID, err)
		} else {
			t.Logf("teardown: deleted app %s", appID)
		}
	})

	// 2. Set the App Store listing (Description + Category are required before deploy).
	if _, err := client.UpdateStoreListing(ctx, appID, map[string]interface{}{
		"store_description": "Ephemeral E2E test app for the privasys CLI live harness.",
		"store_category":    "Developer Tools",
	}); err != nil {
		t.Fatalf("set store listing: %v", err)
	}

	// 3. Record a version from the image.
	if _, err := client.CreateVersion(ctx, appID, map[string]string{"image": image}); err != nil {
		t.Fatalf("create version: %v", err)
	}
	vs, err := client.ListVersions(ctx, appID)
	if err != nil || len(vs) == 0 {
		t.Fatalf("list versions: %v (n=%d)", err, len(vs))
	}
	vid, _ := vs[len(vs)-1]["id"].(string)

	// 3. Resolve a compatible enclave and deploy.
	enclaveID := os.Getenv("PRIVASYS_E2E_ENCLAVE")
	if enclaveID == "" {
		encs, err := client.CompatibleEnclaves(ctx, appID)
		if err != nil {
			t.Fatalf("compatible enclaves: %v", err)
		}
		if len(encs) == 0 {
			t.Fatal("no compatible enclaves")
		}
		enclaveID, _ = encs[0]["id"].(string)
	}
	t.Logf("deploying %s -> enclave %s", name, enclaveID)
	dep, err := client.DeployVersion(ctx, appID, vid, enclaveID, "")
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	depID, _ := dep["id"].(string)
	t.Logf("deployment %s started", depID)

	// 4. Wait for the deployment to come up.
	host := waitDeployed(t, ctx, client, issuer, appID, depID)
	t.Logf("deployment active at %s", host)

	// 5. Verify it by attestation (real RA-TLS challenge + quote check).
	attTok, _ := auth.AccessTokenForAudience(ctx, issuer, "attestation-server")
	res, err := ratls.Verify(ctx, ratls.Params{
		Host: host, ServerName: host, Challenge: ratls.NewNonce(),
		AttServerURL: "https://as.privasys.org/verify", AttServerTok: attTok,
	})
	if err != nil {
		t.Fatalf("attest %s: %v", host, err)
	}
	t.Logf("attest %s: verified=%v challenged=%v", host, res.Verified, res.Challenged)
	if !res.Verified {
		t.Fatalf("attestation NOT verified for the freshly deployed app %s", host)
	}
}

// waitDeployed polls until the deployment is active and returns its hostname.
// It refreshes the client's access token each poll so a long deploy outlives the
// token TTL.
func waitDeployed(t *testing.T, ctx context.Context, client *api.Client, issuer, appID, depID string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	lastStatus := ""
	for {
		if tok, terr := auth.AccessToken(ctx, issuer); terr == nil && tok != "" {
			client.Token = tok
		}
		deps, err := client.ListDeployments(ctx, appID)
		if err != nil {
			t.Fatalf("list deployments: %v", err)
		}
		for _, d := range deps {
			if id, _ := d["id"].(string); id != depID {
				continue
			}
			st, _ := d["status"].(string)
			if st != lastStatus {
				t.Logf("deployment %s: status=%q", depID, st)
				lastStatus = st
			}
			switch st {
			case "active", "deployed", "running":
				if h, err := client.ActiveDeploymentHost(ctx, appID); err == nil && h != "" {
					return h
				}
				if h, _ := d["hostname"].(string); h != "" {
					return h
				}
			case "failed", "error", "stopped":
				t.Fatalf("deployment %s ended in status %q", depID, st)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for deployment %s to become active", depID)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled: %v", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
