// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The vaults' token goes only where the control plane calls the vaults.
func TestVaultBearerOnlyOnVaultRoutes(t *testing.T) {
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get(VaultBearerHeader)
		if r.Header.Get("Authorization") != "Bearer platform" {
			t.Errorf("%s: Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "platform")
	c.SetVaultBearer(func(context.Context) (string, error) { return "vaults", nil })

	want := map[string]string{
		"/api/v1/apps/a/versions/v/stage":                 "vaults",
		"/api/v1/apps/a/versions/v/pending":               "vaults",
		"/api/v1/apps/a/policy":                           "vaults",
		"/api/v1/apps/a/retire-measurement":               "vaults",
		"/api/v1/admin/enclaves/e/data-key/pending":       "vaults",
		"/api/v1/apps":                                    "",
		"/api/v1/apps/a":                                  "",
		"/api/v1/admin/enclaves":                          "",
		"/api/v1/apps/a/versions/v/../../../../somewhere": "",
	}
	for p := range want {
		var out map[string]interface{}
		_ = c.getJSON(context.Background(), p, &out)
	}
	for p, w := range want {
		got, ok := seen[p]
		if !ok {
			continue // a path the client cleaned before sending
		}
		if got != w {
			t.Errorf("%s: vault bearer %q, want %q", p, got, w)
		}
	}

	// No token, no header.
	c2 := New(srv.URL, "platform")
	c2.SetVaultBearer(func(context.Context) (string, error) { return "", nil })
	var out map[string]interface{}
	_ = c2.getJSON(context.Background(), "/api/v1/apps/b/policy", &out)
	if seen["/api/v1/apps/b/policy"] != "" {
		t.Error("an empty vault bearer was sent")
	}
}
