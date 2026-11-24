// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

// versionsServer lists versions newest first, as the control plane does, and
// the given deployments.
func versionsServer(t *testing.T, deployments []map[string]string) *api.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"versions": []map[string]interface{}{
				{"id": "v-3", "version_number": 3}, {"id": "v-2", "version_number": 2}, {"id": "v-1", "version_number": 1},
			}})
		case strings.HasSuffix(r.URL.Path, "/deployments"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"deployments": deployments})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return api.New(srv.URL, "tok")
}

func TestNoVersionMeansTheNewest(t *testing.T) {
	c := versionsServer(t, nil)
	vid, err := resolveVersionRef(context.Background(), c, "app", "")
	if err != nil || vid != "v-3" {
		t.Fatalf("got %q, %v; want the newest, v-3 (the list is newest first)", vid, err)
	}
	if vid, _ := resolveVersionRef(context.Background(), c, "app", "2"); vid != "v-2" {
		t.Fatalf("by number: %q", vid)
	}
}

func TestRotateKeyDefaultsToTheRunningVersion(t *testing.T) {
	c := versionsServer(t, []map[string]string{
		{"id": "d-old", "status": "stopped", "version_id": "v-1"},
		{"id": "d-now", "status": "running", "version_id": "v-2"},
	})
	if vid, err := runningVersion(context.Background(), c, "app"); err != nil || vid != "v-2" {
		t.Fatalf("got %q, %v; want the running v-2, not the newest or the oldest", vid, err)
	}

	if _, err := runningVersion(context.Background(), versionsServer(t, []map[string]string{{"status": "stopped", "version_id": "v-1"}}), "app"); err == nil {
		t.Error("no running deployment was accepted")
	}
	two := versionsServer(t, []map[string]string{{"status": "running", "version_id": "v-1"}, {"status": "active", "version_id": "v-2"}})
	if _, err := runningVersion(context.Background(), two, "app"); err == nil || !strings.Contains(err.Error(), "name the version") {
		t.Errorf("two running versions: %v", err)
	}
}
