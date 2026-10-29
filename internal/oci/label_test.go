// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	cases := map[string]Ref{
		"ghcr.io/privasys/diom-dar@sha256:f695627d68a6bedada89f56ee32004f20d392cf9f94ee610af2b13a7d96ace6b": {
			Registry: "ghcr.io", Repo: "privasys/diom-dar",
			Digest: "sha256:f695627d68a6bedada89f56ee32004f20d392cf9f94ee610af2b13a7d96ace6b",
		},
		"ghcr.io/privasys/diom-dar:v0.1.0": {Registry: "ghcr.io", Repo: "privasys/diom-dar", Tag: "v0.1.0"},
		"localhost:5000/a/b:1":             {Registry: "localhost:5000", Repo: "a/b", Tag: "1"},
		"alpine":                           {Registry: "registry-1.docker.io", Repo: "library/alpine"},
	}
	for in, want := range cases {
		got, err := ParseRef(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
	}
	if _, err := ParseRef("ghcr.io/x/y@sha256:short"); err == nil {
		t.Error("bad digest accepted")
	}
}

// A private registry: every request needs a bearer token, and the token
// service only issues one when the realm receives the credential.
func TestFetchLabelPrivateImageWithCredential(t *testing.T) {
	manifest := map[string]any{"tools": []any{map[string]any{"name": "configure"}}, "config_api": map[string]any{"path": "/configure"}}
	manifestJSON, _ := json.Marshal(manifest)
	labelValue := base64.StdEncoding.EncodeToString(manifestJSON)
	config, _ := json.Marshal(map[string]any{"config": map[string]any{"Labels": map[string]string{
		"org.privasys.manifest": labelValue,
	}}})
	const configDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const platformDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	tokenCalls, authedTokenCalls := 0, 0

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			tokenCalls++
			if u, p, ok := r.BasicAuth(); !ok || u != "x-access-token" || p != "ghp_secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			authedTokenCalls++
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "T"})
		case r.Header.Get("Authorization") != "Bearer T":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="reg",scope="repository:org/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasSuffix(r.URL.Path, "/manifests/v1"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mediaType": "application/vnd.oci.image.index.v1+json",
				"manifests": []any{
					map[string]any{"digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333", "platform": map[string]string{"os": "unknown", "architecture": "unknown"}, "annotations": map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
					map[string]any{"digest": platformDigest, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/manifests/"+platformDigest):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]string{"digest": configDigest}})
		case strings.HasSuffix(r.URL.Path, "/blobs/"+configDigest):
			_, _ = w.Write(config)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewClient()
	c.Scheme = "http"
	host := strings.TrimPrefix(srv.URL, "http://")
	got, err := c.FetchLabel(context.Background(), host+"/org/app:v1", "org.privasys.manifest", &Credential{Password: "ghp_secret"})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil || back["config_api"] == nil {
		t.Fatalf("label not decoded: %s %v", got, err)
	}
	if authedTokenCalls != 1 || tokenCalls != 1 {
		t.Errorf("token exchanges: %d total, %d with credential", tokenCalls, authedTokenCalls)
	}

	// Without the credential the token service refuses and the fetch fails
	// clearly, which is exactly the control plane's position.
	if _, err := c.FetchLabel(context.Background(), host+"/org/app:v1", "org.privasys.manifest", nil); err == nil {
		t.Error("anonymous fetch of a private image succeeded")
	}
}

func TestDecodeLabel(t *testing.T) {
	if _, err := DecodeLabel(`{"a":1}`); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLabel(base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLabel("not json"); err == nil {
		t.Error("garbage accepted")
	}
}
