// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

// The wallet push names a vault key by owner-given names only: the key and its
// key vault, never the vault's id.
func TestVaultKeyDisplayName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/keyvaults" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"vaults":[{"id":"6f186e39-aaaa","name":"wallet-card-test"}]}`))
	}))
	defer srv.Close()
	c := api.New(srv.URL, "tok")
	ctx := context.Background()

	if got := vaultKeyDisplayName(ctx, c, "6f186e39-aaaa", "card1"); got != "key card1 in vault wallet-card-test" {
		t.Fatalf("got %q", got)
	}
	if got := vaultKeyDisplayName(ctx, c, "unknown", "card1"); got != "key card1" {
		t.Fatalf("unknown vault: got %q", got)
	}
}
