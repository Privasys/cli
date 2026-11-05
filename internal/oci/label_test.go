// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		"docker.io/org/app:1":              {Registry: "registry-1.docker.io", Repo: "org/app", Tag: "1"},
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

func TestRealmAllowed(t *testing.T) {
	cases := []struct {
		registry, realm string
		want            bool
	}{
		{"ghcr.io", "https://ghcr.io/token", true},
		{"registry.gitlab.com", "https://gitlab.com/jwt/auth", true},
		{"registry-1.docker.io", "https://auth.docker.io/token", true},
		{"reg.example.com:5000", "https://reg.example.com:5000/token", true},
		{"ghcr.io", "https://evil.example/token", false},
		{"ghcr.io", "https://ghcr.io.evil.example/token", false},
		{"ghcr.io", "https://notghcr.io/token", false},
		{"reg.example.com", "https://com/token", false},
		{"reg.example.com", "https://other.example.com/token", false},
		{"evil.example", "https://auth.docker.io/token", false},
	}
	for _, c := range cases {
		u, err := url.Parse(c.realm)
		if err != nil {
			t.Fatal(err)
		}
		if got := realmAllowed(c.registry, u); got != c.want {
			t.Errorf("realmAllowed(%s, %s) = %v", c.registry, c.realm, got)
		}
	}
}

// The credential must not reach a token service the registry merely names: not
// another host, and not through a redirect from the realm.
func TestCredentialStaysWithTheRegistry(t *testing.T) {
	leaked := false
	thief := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			leaked = true
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "T"})
	}))
	defer thief.Close()

	var realm string
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			http.Redirect(w, r, thief.URL+"/token", http.StatusFound)
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer realm=\""+realm+"\",service=\"reg\"")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer reg.Close()
	host := strings.TrimPrefix(reg.URL, "http://")

	cred := &Credential{Password: "ghp_secret"}
	for name, r := range map[string]string{
		"another host":        thief.URL + "/token",
		"redirect from realm": reg.URL + "/token",
	} {
		realm = r
		c := NewClient()
		c.Scheme = "http"
		if _, err := c.FetchLabel(context.Background(), host+"/org/app:v1", "org.privasys.manifest", cred); err == nil {
			t.Errorf("%s: fetch succeeded", name)
		}
		if leaked {
			t.Fatalf("%s: the credential reached another host", name)
		}
	}

	// In production, an http realm on the registry's own host is refused too.
	s := &session{c: NewClient(), registry: host, repo: "org/app", cred: cred}
	err := s.exchange(context.Background(), "Bearer realm=\""+reg.URL+"/token\",service=\"reg\"")
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("http realm: %v", err)
	}
}
