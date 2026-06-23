// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testClient(t *testing.T, h http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	return New(srv.URL, "test-token"), srv.Close
}

func TestCreateApp(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/apps" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bearer token")
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "demo" || body["source_type"] != "github" {
			t.Errorf("bad body: %v", body)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"id": "app-1", "name": "demo", "status": "submitted"})
	})
	defer done()

	app, err := c.CreateApp(context.Background(), map[string]interface{}{"name": "demo", "source_type": "github"})
	if err != nil {
		t.Fatal(err)
	}
	if app["id"] != "app-1" {
		t.Fatalf("got %v", app)
	}
}

func TestVersionsAndDeploy(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/apps/app-1/versions":
			// bare array form
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "v1", "version_number": 1, "status": "built"},
				{"id": "v2", "version_number": 2, "status": "built"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apps/app-1/versions":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["commit_url"] == "" {
				t.Error("missing commit_url")
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"id": "v3", "status": "pending"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apps/app-1/versions/v2/deploy":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["enclave_id"] != "enc-9" {
				t.Errorf("bad enclave_id: %v", b)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"id": "dep-1", "status": "starting"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	defer done()
	ctx := context.Background()

	vs, err := c.ListVersions(ctx, "app-1")
	if err != nil || len(vs) != 2 {
		t.Fatalf("versions: %v %v", vs, err)
	}
	v, err := c.CreateVersion(ctx, "app-1", map[string]string{"commit_url": "https://github.com/x/y/commit/abc"})
	if err != nil || v["id"] != "v3" {
		t.Fatalf("createVersion: %v %v", v, err)
	}
	dep, err := c.DeployVersion(ctx, "app-1", "v2", "enc-9")
	if err != nil || dep["id"] != "dep-1" {
		t.Fatalf("deploy: %v %v", dep, err)
	}
}

func TestSchemaUnwrap(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "schema",
			"schema": map[string]interface{}{
				"name":      "demo",
				"functions": []map[string]interface{}{{"name": "hello", "params": []interface{}{}, "results": []interface{}{map[string]interface{}{"name": "s", "type": "string"}}}},
			},
		})
	})
	defer done()
	s, err := c.Schema(context.Background(), "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if s["name"] != "demo" {
		t.Fatalf("schema not unwrapped: %v", s)
	}
}

// App function calls are direct over RA-TLS now (internal/ratls.Call); there
// is no control-plane RPC method to test here.

func TestUploadCwasm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.cwasm")
	if err := os.WriteFile(path, []byte("\x00asm-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		mt, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mt != "multipart/form-data" {
			t.Fatalf("not multipart: %s", r.Header.Get("Content-Type"))
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		f, hdr, err := r.FormFile("file")
		if err != nil {
			t.Fatalf("FormFile: %v", err)
		}
		defer f.Close()
		if hdr.Filename != "app.cwasm" {
			t.Errorf("filename %q", hdr.Filename)
		}
		_ = params
		json.NewEncoder(w).Encode(map[string]interface{}{"id": "app-1", "cwasm_hash": "deadbeef"})
	})
	defer done()
	app, err := c.UploadCwasm(context.Background(), "app-1", path)
	if err != nil {
		t.Fatal(err)
	}
	if app["cwasm_hash"] != "deadbeef" {
		t.Fatalf("got %v", app)
	}
}

func TestErrorStatus(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"nope"}`))
	})
	defer done()
	if _, err := c.ListVersions(context.Background(), "app-1"); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected auth error, got %v", err)
	}
}
