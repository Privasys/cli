// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

var clearRoutes = []string{"static /", "GET /api/v1/public/status"}

// surfacesPlatform refuses to deploy or stage until the version's clear routes
// are confirmed, exactly as the control plane does, and records what was sent.
type surfacesPlatform struct {
	*httptest.Server
	confirmed []string // entries the confirm endpoint received
	shipped   int      // deploys/stages that went through
}

func newSurfacesPlatform(t *testing.T) *surfacesPlatform {
	t.Helper()
	p := &surfacesPlatform{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && path == "/api/v1/apps/app-1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "app-1", "name": "demo", "app_type": "container"})
		case r.Method == http.MethodGet && path == "/api/v1/apps/app-1/versions/ver-1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "ver-1", "surfaces": map[string]interface{}{
				"static": []string{"/"},
				"public": []map[string]string{{"method": "get", "path": "/api/v1/public/status"}},
			}})
		case r.Method == http.MethodPost && path == "/api/v1/apps/app-1/versions/ver-1/surfaces/confirm":
			var body struct {
				Entries []string `json:"entries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			p.confirmed = body.Entries
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "ver-1", "surfaces_confirmed_by": "owner"})
		case r.Method == http.MethodPost && (strings.HasSuffix(path, "/deploy") || strings.HasSuffix(path, "/stage")):
			if p.confirmed == nil {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   api.SurfacesConfirmationRequired,
					"message": "this version serves routes in the clear that no owner has confirmed",
					"entries": clearRoutes, "added": clearRoutes[1:],
				})
				return
			}
			p.shipped++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "dep-1", "status": "deploying"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *surfacesPlatform) call(t *testing.T, tool string, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	srv := NewServer(func(ctx context.Context) (Deps, error) {
		return Deps{Client: api.New(p.URL, "tok"), Token: "h.e30.s", Authed: true}, nil
	}, "test")
	a, _ := json.Marshal(args)
	resps := run(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+string(a)+`}}`)
	res := resps[0]["result"].(map[string]interface{})
	text := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if res["isError"] == true {
		t.Fatalf("%s: tool error: %s", tool, text)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s: result is not JSON: %s", tool, text)
	}
	return out
}

// Without the owner's confirmation nothing ships and nothing is confirmed:
// the tool hands the routes back for review instead of a bare 409.
func TestShippingToolsAskForSurfacesReview(t *testing.T) {
	cases := []struct {
		tool string
		args map[string]interface{}
	}{
		{"apps_deploy", map[string]interface{}{"app_id": "app-1", "version": "ver-1", "location": "eu"}},
		{"apps_versions_stage", map[string]interface{}{"app_id": "app-1", "version": "ver-1", "enclave": "enc-1"}},
		{"apps_update", map[string]interface{}{"app_id": "app-1", "version": "ver-1", "location": "eu"}},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			p := newSurfacesPlatform(t)
			out := p.call(t, c.tool, c.args)
			if out["surfaces_confirmation_required"] != true || out["shipped"] != false {
				t.Fatalf("want a surfaces review, got %v", out)
			}
			if got, _ := json.Marshal(out["routes_in_clear"]); string(got) != `["static /","GET /api/v1/public/status"]` {
				t.Errorf("routes_in_clear = %s", got)
			}
			if p.confirmed != nil || p.shipped != 0 {
				t.Errorf("confirmed %v / shipped %d without the owner's answer", p.confirmed, p.shipped)
			}
		})
	}
}

// With confirm_surfaces the tool records exactly the platform's entries, then
// ships.
func TestShippingToolsRecordConfirmationAndShip(t *testing.T) {
	p := newSurfacesPlatform(t)
	out := p.call(t, "apps_deploy", map[string]interface{}{
		"app_id": "app-1", "version": "ver-1", "location": "eu", "confirm_surfaces": true,
	})
	if out["id"] != "dep-1" || p.shipped != 1 {
		t.Fatalf("want the deployment after confirming, got %v (shipped %d)", out, p.shipped)
	}
	if strings.Join(p.confirmed, "|") != strings.Join(clearRoutes, "|") {
		t.Errorf("confirmed %v, want the platform's own entries %v", p.confirmed, clearRoutes)
	}
}

// The standalone tool is two-phase too: it lists, and records only on confirm.
func TestConfirmSurfacesToolIsTwoPhase(t *testing.T) {
	p := newSurfacesPlatform(t)
	args := map[string]interface{}{"app_id": "app-1", "version": "ver-1"}
	out := p.call(t, "apps_versions_confirm_surfaces", args)
	if out["confirmed"] != false || p.confirmed != nil {
		t.Fatalf("first call must only list, got %v (recorded %v)", out, p.confirmed)
	}
	args["confirm"] = true
	p.call(t, "apps_versions_confirm_surfaces", args)
	if strings.Join(p.confirmed, "|") != strings.Join(clearRoutes, "|") {
		t.Errorf("recorded %v, want %v", p.confirmed, clearRoutes)
	}
}

func TestAllowedCallersDocument(t *testing.T) {
	doc, err := allowedCallersDocument(`[{"app_id":"a"}]`, true, []string{"p1"})
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != `{"entries":[{"app_id":"a"},{"app_id":"*"}],"platforms":["p1"]}` {
		t.Errorf("doc = %s", doc)
	}
	if _, err := allowedCallersDocument("", true, nil); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Errorf("any_attested without platforms must be refused, got %v", err)
	}
	doc, err = allowedCallersDocument(`{"entries":[],"platforms":["p0"]}`, true, []string{"p1"})
	if err != nil || string(doc) != `{"entries":[{"app_id":"*"}],"platforms":["p0","p1"]}` {
		t.Errorf("document form: %s, %v", doc, err)
	}
}

// TestToolDecorations holds every tool to the same bar: a real description,
// every property described, required fields that exist, and enums non-empty.
func TestToolDecorations(t *testing.T) {
	srv := NewServer(nil, "test")
	seen := map[string]bool{}
	for _, tl := range srv.tools {
		if seen[tl.Name] {
			t.Errorf("duplicate tool %s", tl.Name)
		}
		seen[tl.Name] = true
		if len(tl.Description) < 30 {
			t.Errorf("%s: description too thin (%q)", tl.Name, tl.Description)
		}
		props, _ := tl.Schema["properties"].(map[string]interface{})
		for name, v := range props {
			p, _ := v.(map[string]interface{})
			if d, _ := p["description"].(string); strings.TrimSpace(d) == "" {
				t.Errorf("%s.%s: no description", tl.Name, name)
			}
			if e, ok := p["enum"].([]string); ok && len(e) == 0 {
				t.Errorf("%s.%s: empty enum", tl.Name, name)
			}
		}
		req, _ := tl.Schema["required"].([]string)
		for _, r := range req {
			if _, ok := props[r]; !ok {
				t.Errorf("%s: required %q is not a property", tl.Name, r)
			}
		}
	}
}
