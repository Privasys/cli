// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

func run(t *testing.T, srv *Server, requests ...string) []map[string]interface{} {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var resps []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

func TestMCPInitializeAndList(t *testing.T) {
	srv := NewServer(func(ctx context.Context) (Deps, error) { return Deps{}, nil }, "v9.9.9")
	resps := run(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // no response expected
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	)
	if len(resps) != 2 {
		t.Fatalf("expected 2 responses (notification suppressed), got %d", len(resps))
	}
	init := resps[0]["result"].(map[string]interface{})
	if init["protocolVersion"] != protocolVersion {
		t.Errorf("proto = %v", init["protocolVersion"])
	}
	tools := resps[1]["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) < 15 {
		t.Errorf("expected the full tool surface, got %d", len(tools))
	}
}

func TestMCPToolCall(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/apps" {
			json.NewEncoder(w).Encode([]map[string]interface{}{{"id": "app-1", "name": "demo"}})
			return
		}
		http.NotFound(w, r)
	}))
	defer backend.Close()

	srv := NewServer(func(ctx context.Context) (Deps, error) {
		return Deps{Client: api.New(backend.URL, "tok"), Token: "h.e30.s", Authed: true}, nil
	}, "v1")

	resps := run(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apps_list","arguments":{}}}`)
	res := resps[0]["result"].(map[string]interface{})
	if res["isError"] == true {
		t.Fatalf("unexpected tool error: %v", res)
	}
	content := res["content"].([]interface{})[0].(map[string]interface{})
	if !strings.Contains(content["text"].(string), "app-1") {
		t.Errorf("tool result missing app: %v", content["text"])
	}
}

func TestMCPNoAuthGate(t *testing.T) {
	// Unauthenticated deps (Authed=false): onboarding tools run, others reject.
	srv := NewServer(func(ctx context.Context) (Deps, error) {
		return Deps{Issuer: "https://privasys.id", Endpoint: "http://x"}, nil
	}, "v1")

	// auth_status (noAuth) succeeds and reports not-authenticated.
	resps := run(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"auth_status","arguments":{}}}`)
	res := resps[0]["result"].(map[string]interface{})
	if res["isError"] == true {
		t.Fatalf("auth_status should run unauthenticated: %v", res)
	}
	if txt := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string); !strings.Contains(txt, "\"authenticated\": false") {
		t.Errorf("auth_status should report not authenticated, got %v", txt)
	}

	// apps_list (auth-required) is rejected with the not-authenticated error.
	resps = run(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"apps_list","arguments":{}}}`)
	res = resps[0]["result"].(map[string]interface{})
	if res["isError"] != true {
		t.Fatalf("apps_list should reject unauthenticated, got %v", res)
	}
	if txt := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string); !strings.Contains(txt, "not authenticated") {
		t.Errorf("expected not-authenticated message, got %v", txt)
	}
}

func TestMCPUnknownTool(t *testing.T) {
	srv := NewServer(func(ctx context.Context) (Deps, error) { return Deps{}, nil }, "v1")
	resps := run(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if resps[0]["error"] == nil {
		t.Errorf("expected error for unknown tool, got %v", resps[0])
	}
}

func TestMCPMissingRequiredArg(t *testing.T) {
	srv := NewServer(func(ctx context.Context) (Deps, error) { return Deps{Client: api.New("http://x", "t"), Authed: true}, nil }, "v1")
	resps := run(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apps_describe","arguments":{}}}`)
	res := resps[0]["result"].(map[string]interface{})
	if res["isError"] != true {
		t.Errorf("expected isError for missing app_id, got %v", res)
	}
}
