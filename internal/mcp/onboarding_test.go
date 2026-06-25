// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
)

// prodDeps mirrors the deps closure cmd/mcp.go builds: Issuer/Endpoint always
// set, and a token/Client when there is a stored session. So onboarding tools
// run before sign-in and auth state becomes visible after auth_poll stores the
// credential, exactly as in production.
func prodDeps(issuer, endpoint string) DepsFunc {
	return func(ctx context.Context) (Deps, error) {
		d := Deps{Issuer: issuer, Endpoint: endpoint}
		if tok, err := auth.AccessToken(ctx, issuer); err == nil {
			d.Token = tok
			d.Client = api.New(endpoint, tok)
			d.Authed = true
		}
		return d, nil
	}
}

// resultText returns a tool call's text content, failing on a tool error.
func resultText(t *testing.T, byID map[float64]map[string]interface{}, id float64) string {
	t.Helper()
	res, ok := byID[id]["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("id %v: no result: %v", id, byID[id])
	}
	if res["isError"] == true {
		t.Fatalf("id %v: unexpected tool error: %v", id, res["content"])
	}
	return res["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
}

func indexByID(resps []map[string]interface{}) map[float64]map[string]interface{} {
	out := map[float64]map[string]interface{}{}
	for _, r := range resps {
		if id, ok := r["id"].(float64); ok {
			out[id] = r
		}
	}
	return out
}

// TestMCPOnboardingFlow (L2) drives the MCP server over the JSON-RPC loop
// through the full cold-start onboarding sequence against mocks: sign in
// (account/payment external, the agent polls), then create a confidential app
// with encrypted storage, ship a version, deploy, and start a subscription.
func TestMCPOnboardingFlow(t *testing.T) {
	keyring.MockInit()
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())
	idp := newMockIdP(t)
	mgmt := newMockMgmt(t)

	srv := NewServer(prodDeps(idp.URL, mgmt.URL), "test")

	resps := run(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"auth_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"auth_begin","arguments":{"agent":"Claude"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"auth_poll","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"auth_poll","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"auth_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"apps_create","arguments":{"name":"userdata-db","source_type":"package","app_type":"container","image":"ghcr.io/acme/userdata-db:v1","storage":true}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"apps_versions_create","arguments":{"app_id":"app-1","image":"ghcr.io/acme/userdata-db:v1"}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"apps_deploy","arguments":{"app_id":"app-1","version":"ver-1","enclave":"enc-1"}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"billing_subscribe","arguments":{}}}`,
	)
	byID := indexByID(resps)

	if !strings.Contains(resultText(t, byID, 2), `"authenticated": false`) {
		t.Error("step 2: should start unauthenticated")
	}
	begin := resultText(t, byID, 3)
	if !strings.Contains(begin, "WXYZ-1234") {
		t.Error("auth_begin should surface the user code")
	}
	// The device_code + PKCE verifier must never reach the agent (the model).
	if strings.Contains(begin, "dev-secret-1") || strings.Contains(begin, "verifier") {
		t.Errorf("auth_begin leaked a device secret into the tool result: %s", begin)
	}
	if !strings.Contains(resultText(t, byID, 4), `"status": "pending"`) {
		t.Error("first auth_poll should be pending")
	}
	if !strings.Contains(resultText(t, byID, 5), `"status": "authenticated"`) {
		t.Error("second auth_poll should authenticate")
	}
	if !strings.Contains(resultText(t, byID, 6), `"authenticated": true`) {
		t.Error("step 6: should be authenticated after the poll stored the session")
	}
	if !strings.Contains(resultText(t, byID, 7), "app-1") {
		t.Error("apps_create should return the new app")
	}
	if mgmt.lastCreate["container_storage"] != true {
		t.Errorf("apps_create should request encrypted storage, got body %v", mgmt.lastCreate)
	}
	if !strings.Contains(resultText(t, byID, 8), "ver-1") {
		t.Error("apps_versions_create should return a version")
	}
	if !strings.Contains(resultText(t, byID, 9), "dep-1") {
		t.Error("apps_deploy should return a deployment")
	}
	if !strings.Contains(resultText(t, byID, 10), "checkout.stripe.test") {
		t.Error("billing_subscribe should return a checkout URL")
	}
}

// TestMCPKeyOpsTools (L1) covers the data-protection parity tools, asserting the
// request bodies the CLI sends.
func TestMCPKeyOpsTools(t *testing.T) {
	keyring.MockInit()
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())
	mgmt := newMockMgmt(t)

	// Authed deps (these tools require a session); no IdP round-trip needed.
	srv := NewServer(func(ctx context.Context) (Deps, error) {
		return Deps{Issuer: "https://privasys.id", Endpoint: mgmt.URL,
			Token: "h.e30.s", Client: api.New(mgmt.URL, "t"), Authed: true}, nil
	}, "test")

	resps := run(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apps_cosign","arguments":{"app_id":"app-1","enable":true}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"apps_migrate_constellation","arguments":{"app_id":"app-1","target":"con-2"}}}`,
	)
	byID := indexByID(resps)

	resultText(t, byID, 1) // fails the test on a tool error
	if mgmt.lastCosign["require_cosign"] != true {
		t.Errorf("apps_cosign should send require_cosign=true, got %v", mgmt.lastCosign)
	}
	resultText(t, byID, 2)
	if mgmt.migrateHit != "/api/v1/apps/app-1/migrate-constellation" {
		t.Errorf("apps_migrate_constellation hit %q", mgmt.migrateHit)
	}
}
