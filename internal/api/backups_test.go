// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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

// A policy change sends only what changes: the platform keeps the rest.
func TestSetBackupPolicySendsOnlyChanges(t *testing.T) {
	cases := []struct {
		interval, retention, redundancy string
		want                            map[string]string
	}{
		{"daily", "", "", map[string]string{"interval": "daily"}},
		{"", "", "zones", map[string]string{"redundancy": "zones"}},
		{"hourly", "minimal", "region", map[string]string{"interval": "hourly", "retention": "minimal", "redundancy": "region"}},
	}
	for _, tc := range cases {
		c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/api/v1/apps/app-1/backups/policy" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if len(body) != len(tc.want) {
				t.Errorf("body %v, want %v", body, tc.want)
			}
			for k, v := range tc.want {
				if body[k] != v {
					t.Errorf("%s = %q, want %q", k, body[k], v)
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true})
		})
		if _, err := c.SetBackupPolicy(context.Background(), "app-1", tc.interval, tc.retention, tc.redundancy); err != nil {
			t.Error(err)
		}
		done()
	}
}

// A live app's access goes through the app; kept backups through /backups.
func TestBackupAccessPaths(t *testing.T) {
	var calls []string
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		json.NewEncoder(w).Encode(map[string]interface{}{"exists": false})
	})
	defer done()
	ctx := context.Background()
	for _, live := range []bool{true, false} {
		if _, err := c.GetBackupAccess(ctx, "app-1", live); err != nil {
			t.Fatal(err)
		}
		if _, err := c.CreateBackupAccess(ctx, "app-1", live); err != nil {
			t.Fatal(err)
		}
		if err := c.RevokeBackupAccess(ctx, "app-1", live); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"GET /api/v1/apps/app-1/backups/access", "POST /api/v1/apps/app-1/backups/access", "DELETE /api/v1/apps/app-1/backups/access",
		"GET /api/v1/backups/app-1/access", "POST /api/v1/backups/app-1/access", "DELETE /api/v1/backups/app-1/access",
	}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v", calls)
	}
}
