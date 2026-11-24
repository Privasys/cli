// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

// A write tool run in a chosen account names the account in its result; a
// read names nothing.
func TestToolResultNamesTheAccountOfAWrite(t *testing.T) {
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer mgmt.Close()
	deps := func(ctx context.Context) (Deps, error) {
		c := api.New(mgmt.URL, "tok")
		var acted string
		c.SetAccount("acc-1", func(context.Context, *api.Client) { acted = "E2E Tests (acc-1)" })
		return Deps{Client: c, Token: "tok", Authed: true, ActedIn: func() string { return acted }}, nil
	}
	s := NewServer(deps, "test")
	call := func(name string, args map[string]interface{}) []map[string]interface{} {
		params, _ := json.Marshal(map[string]interface{}{"name": name, "arguments": args})
		res := s.callTool(context.Background(), &rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Params: params})
		return res.Result.(map[string]interface{})["content"].([]map[string]interface{})
	}
	if c := call("apps_list", nil); len(c) != 1 {
		t.Fatalf("a read named an account: %v", c)
	}
	c := call("apps_create", map[string]interface{}{"name": "x", "source_type": "container", "container_image": "ghcr.io/a/b:1"})
	if len(c) != 2 || c[1]["text"] != "Acted in account E2E Tests (acc-1)" {
		t.Fatalf("the write's result: %v", c)
	}
}
