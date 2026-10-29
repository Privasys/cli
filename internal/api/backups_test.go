// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Deleting an app keeps its volume and backups unless asked, and hands back the
// platform's message saying what was kept.
func TestDeleteAppWith(t *testing.T) {
	cases := []struct {
		volume, backups bool
		query           string
	}{
		{false, false, ""},
		{true, false, "with_volume=true"},
		{false, true, "with_backups=true"},
		{true, true, "with_backups=true&with_volume=true"},
	}
	for _, tc := range cases {
		c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/apps/app-1" || r.URL.RawQuery != tc.query {
				t.Errorf("unexpected %s %s?%s, want query %q", r.Method, r.URL.Path, r.URL.RawQuery, tc.query)
			}
			json.NewEncoder(w).Encode(map[string]string{"message": "app deleted; kept"})
		})
		msg, err := c.DeleteAppWith(context.Background(), "app-1", tc.volume, tc.backups)
		done()
		if err != nil || msg != "app deleted; kept" {
			t.Errorf("%+v: msg %q, err %v", tc, msg, err)
		}
	}
}

func TestBackupSets(t *testing.T) {
	var calls []string
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodDelete {
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"backups": []interface{}{}})
	})
	defer done()
	ctx := context.Background()
	if _, err := c.ListBackupSets(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetBackupSet(ctx, "app-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteBackupSet(ctx, "app-1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /api/v1/backups", "GET /api/v1/backups/app-1", "DELETE /api/v1/backups/app-1"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, calls[i], want[i])
		}
	}
}
