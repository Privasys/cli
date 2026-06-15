// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAccountAndMembers(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/account":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"account": map[string]interface{}{"id": "acc-1", "name": "Acme", "kind": "org"},
				"role":    "admin",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/account/members":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"members":   []map[string]interface{}{{"sub": "u1", "role": "admin"}},
				"owner_sub": "u1",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/account/members":
			var b map[string]interface{}
			json.NewDecoder(r.Body).Decode(&b)
			if b["sub"] != "u2" || b["role"] != "member" {
				t.Errorf("bad add body: %v", b)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"members": []map[string]interface{}{{"sub": "u1", "role": "admin"}, {"sub": "u2", "role": "member"}},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/account/members/u2":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["role"] != "billing" {
				t.Errorf("bad role: %v", b)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"members": []map[string]interface{}{{"sub": "u2", "role": "billing"}}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/account/members/u2":
			json.NewEncoder(w).Encode(map[string]interface{}{"members": []map[string]interface{}{{"sub": "u1"}}})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	defer done()
	ctx := context.Background()

	view, err := c.GetAccount(ctx)
	if err != nil || view["role"] != "admin" {
		t.Fatalf("account: %v %v", view, err)
	}
	if _, err := c.ListMembers(ctx); err != nil {
		t.Fatal(err)
	}
	add, err := c.AddMember(ctx, map[string]interface{}{"sub": "u2", "role": "member"})
	if err != nil {
		t.Fatal(err)
	}
	if ms, _ := add["members"].([]interface{}); len(ms) != 2 {
		t.Fatalf("expected 2 members, got %v", add["members"])
	}
	if _, err := c.SetMemberRole(ctx, "u2", "billing"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveMember(ctx, "u2"); err != nil {
		t.Fatal(err)
	}
}

func TestAppOwners(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apps/app-1/owners":
			var b map[string]interface{}
			json.NewDecoder(r.Body).Decode(&b)
			if b["sub"] != "u3" {
				t.Errorf("bad owner: %v", b)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"owners": []map[string]interface{}{{"sub": "u3"}}, "creator_sub": "u1"})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/apps/app-1/owners/u3":
			json.NewEncoder(w).Encode(map[string]interface{}{"owners": []map[string]interface{}{}, "creator_sub": "u1"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	defer done()
	ctx := context.Background()
	if _, err := c.AddAppOwner(ctx, "app-1", map[string]interface{}{"sub": "u3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveAppOwner(ctx, "app-1", "u3"); err != nil {
		t.Fatal(err)
	}
}

// Attestation is client-side only now (see internal/ratls); there is no
// management-service attest method to test here.
