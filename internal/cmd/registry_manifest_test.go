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

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
)

func TestApproveImageHost(t *testing.T) {
	cmd := &cobra.Command{}
	env := &Env{NoInput: true}
	cases := []struct {
		image, host, wantErr string
	}{
		{"ghcr.io/org/app:v1", "ghcr.io", ""},
		{"ghcr.io/org/app:v1", "GHCR.io", ""},
		{"docker.io/org/app:v1", "docker.io", ""},
		{"org/app:v1", "docker.io", ""},
		{"evil.example/org/app:v1", "ghcr.io", "not sent"},
		{"ghcr.io.evil.example/org/app", "ghcr.io", "not sent"},
		// Nobody to ask: it names the host and sends nothing.
		{"ghcr.io/org/app:v1", "", "--image-host ghcr.io"},
	}
	for _, c := range cases {
		err := approveImageHost(cmd, env, c.image, c.host)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s with %q: %v", c.image, c.host, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s with %q: want %q, got %v", c.image, c.host, c.wantErr, err)
		}
	}
}

// When the control plane names another host, nothing is contacted with the
// credential and nothing is recorded.
func TestRecordManifestRefusesAnUnexpectedHost(t *testing.T) {
	registryHits := 0
	registry := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { registryHits++ }))
	defer registry.Close()
	host := strings.TrimPrefix(registry.URL, "http://")

	patched := false
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patched = true
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": "app-1", "source_type": "package", "container_image": host + "/org/app:v1",
		})
	}))
	defer platform.Close()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	client := api.New(platform.URL, "tok")
	if _, err := recordManifestFromImage(cmd, &Env{NoInput: true}, client, "app-1", "", "ghp_secret", "ghcr.io"); err == nil {
		t.Fatal("recorded from an image on an unexpected host")
	}
	if registryHits != 0 || patched {
		t.Errorf("registry contacted %d times, manifest recorded: %v", registryHits, patched)
	}
}

// Only a package app's image holds a manifest to read: a built app's image is
// the platform's, and the owner's credential has no business going there.
func TestRecordManifestSkipsOtherSources(t *testing.T) {
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": "app-1", "source_type": "github", "container_image": "ghcr.io/org/app:v1",
		})
	}))
	defer platform.Close()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	recorded, err := recordManifestFromImage(cmd, &Env{NoInput: true}, api.New(platform.URL, "tok"), "app-1", "", "ghp_secret", "")
	if recorded || err != nil {
		t.Errorf("recorded %v, err %v", recorded, err)
	}
}
