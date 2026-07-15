// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestListAndGetEnclaves(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/enclaves":
			// The admin endpoint returns a bare array of enclaves.
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "enc-1", "name": "m1-dev", "tee_type": "tdx", "status": "active", "max_apps": 10, "app_count": 3},
				{"id": "enc-2", "name": "sgx-fr-1", "tee_type": "sgx", "status": "active"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/enclaves/enc-1":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": "enc-1", "name": "m1-dev", "tee_type": "tdx", "mr_enclave": "abc123",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	defer done()

	list, err := c.ListEnclaves(context.Background())
	if err != nil {
		t.Fatalf("ListEnclaves: %v", err)
	}
	if len(list) != 2 || list[0]["name"] != "m1-dev" || list[1]["tee_type"] != "sgx" {
		t.Fatalf("unexpected list: %v", list)
	}

	e, err := c.GetEnclave(context.Background(), "enc-1")
	if err != nil {
		t.Fatalf("GetEnclave: %v", err)
	}
	if e["mr_enclave"] != "abc123" {
		t.Fatalf("unexpected enclave: %v", e)
	}
}
