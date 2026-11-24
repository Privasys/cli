// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --account reaches the control plane as X-Privasys-Account on every request,
// and nothing is sent without it.
func TestAccountHeader(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get(AccountHeader))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	ctx := context.Background()

	c := New(srv.URL, "tok")
	c.Account = "a9aa9575-519e-4ea6-a7c1-ddfce88fa146"
	_, _ = c.CreateApp(ctx, map[string]interface{}{"name": "x"}) // do
	var out map[string]any
	_ = c.getJSON(ctx, "/api/v1/apps", &out) // getJSON
	for i, h := range got {
		if h != c.Account {
			t.Fatalf("request %d sent account %q", i, h)
		}
	}
	got = nil
	_, _ = New(srv.URL, "tok").CreateApp(ctx, map[string]interface{}{"name": "x"})
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("an account was sent without one chosen: %q", got)
	}
}
