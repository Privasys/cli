// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mockIdP stands in for privasys.id's device-grant endpoints. It simulates a
// human approving externally: the first /token poll is authorization_pending,
// subsequent polls return tokens (as if the wallet/passkey approved between
// polls). No real WebAuthn — that fidelity is the L3 (live) job.
type mockIdP struct {
	*httptest.Server
	polls int32
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	m := &mockIdP{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device_authorization":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":               "dev-secret-1",
				"user_code":                 "WXYZ-1234",
				"verification_uri":          m.URL + "/device",
				"verification_uri_complete": m.URL + "/device?user_code=WXYZ-1234",
				"qr_payload":                m.URL + "/scp?p=x",
				"expires_in":                600,
				"interval":                  1,
			})
		case "/token":
			if atomic.AddInt32(&m.polls, 1) < 2 {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "at-test",
				"refresh_token": "rt-test",
				"id_token":      "id-test",
				"token_type":    "Bearer",
				"expires_in":    900,
				"scope":         "openid email profile offline_access",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

// mockMgmt stands in for the management-service public API for the onboarding
// and key-lifecycle sequence, capturing the bodies the CLI sends so tests can
// assert request shapes.
type mockMgmt struct {
	*httptest.Server
	lastCreate map[string]interface{}
	lastCosign map[string]interface{}
	migrateHit string
}

func newMockMgmt(t *testing.T) *mockMgmt {
	t.Helper()
	m := &mockMgmt{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case r.Method == http.MethodPost && p == "/api/v1/apps":
			_ = json.NewDecoder(r.Body).Decode(&m.lastCreate)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "app-1", "name": m.lastCreate["name"], "app_type": "container",
				"source_type": m.lastCreate["source_type"], "status": "created",
				"container_storage": m.lastCreate["container_storage"],
			})
		case r.Method == http.MethodGet && p == "/api/v1/apps":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"id": "app-1", "name": "userdata-db"}})
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/deploy"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "dep-1", "status": "deployed", "hostname": "app-1.apps.privasys.org",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/versions"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "ver-1", "version_number": "v1.0.0", "status": "building",
			})
		case r.Method == http.MethodPatch && strings.HasSuffix(p, "/vault-cosign"):
			_ = json.NewDecoder(r.Body).Decode(&m.lastCosign)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"require_cosign": m.lastCosign["require_cosign"]})
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/migrate-constellation"):
			m.migrateHit = p
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "migrating"})
		case r.Method == http.MethodPost && strings.Contains(p, "/billing/checkout/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true, "url": "https://checkout.stripe.test/x"})
		case r.Method == http.MethodPost && p == "/api/v1/billing/portal":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true, "url": "https://portal.stripe.test/x"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}
