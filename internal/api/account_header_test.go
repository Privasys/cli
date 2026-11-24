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

// The chosen account is announced once, before the first write, never for a
// read, and copies of the client (approval-token clients) share it.
func TestAccountAnnouncedOnceBeforeAWrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	n := 0
	c := New(srv.URL, "tok")
	c.SetAccount("acc-1", func(context.Context, *Client) { n++ })
	var out map[string]any
	_ = c.getJSON(ctx, "/api/v1/apps", &out)
	if n != 0 {
		t.Fatal("a read announced the account")
	}
	_, _ = c.CreateApp(ctx, map[string]interface{}{"name": "x"})
	cp := *c
	cp.Token = "approval"
	_, _ = cp.CreateApp(ctx, map[string]interface{}{"name": "y"})
	if n != 1 {
		t.Fatalf("announced %d times, want once", n)
	}
	// No account chosen: nothing to announce.
	m := 0
	d := New(srv.URL, "tok")
	d.SetAccount("", func(context.Context, *Client) { m++ })
	_, _ = d.CreateApp(ctx, map[string]interface{}{"name": "x"})
	if m != 0 || d.Account != "" {
		t.Fatal("announced without an account")
	}
}
