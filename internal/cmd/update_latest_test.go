// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitHub serves the releases page (redirecting to pageLocation, or 404
// when empty) and the API (a rate-limit 403 when apiLimited).
func fakeGitHub(t *testing.T, pageLocation string, apiLimited bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			if pageLocation == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Location", pageLocation)
			w.WriteHeader(http.StatusFound)
		case "/api":
			if apiLimited {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"tag_name":"v0.9.1"}`))
		}
	}))
	t.Cleanup(srv.Close)
	oldPage, oldAPI := releasesLatestPage, releasesAPI
	releasesLatestPage, releasesAPI = srv.URL+"/page", srv.URL+"/api"
	t.Cleanup(func() { releasesLatestPage, releasesAPI = oldPage, oldAPI })
}

// TestLatestFromRedirectIgnoresAPIQuota: the redirect answers even while the
// API quota is exhausted, which is the case users kept hitting.
func TestLatestFromRedirectIgnoresAPIQuota(t *testing.T) {
	fakeGitHub(t, "https://github.com/Privasys/cli/releases/tag/v0.46.2", true)
	v, err := latestReleaseVersion(context.Background())
	if err != nil || v != "0.46.2" {
		t.Fatalf("latestReleaseVersion = %q, %v; want 0.46.2", v, err)
	}
}

// TestLatestFallsBackToAPI: no usable redirect, the API answers.
func TestLatestFallsBackToAPI(t *testing.T) {
	fakeGitHub(t, "", false)
	v, err := latestReleaseVersion(context.Background())
	if err != nil || v != "0.9.1" {
		t.Fatalf("latestReleaseVersion = %q, %v; want 0.9.1 from the API", v, err)
	}
}

// TestLatestRejectsNonTagRedirect: a redirect elsewhere (a login page, the
// releases list) is not taken for a version; with the API limited too, the
// error names both.
func TestLatestRejectsNonTagRedirect(t *testing.T) {
	fakeGitHub(t, "https://github.com/login?return_to=x", true)
	_, err := latestReleaseVersion(context.Background())
	if err == nil {
		t.Fatal("want an error, got a version")
	}
	for _, want := range []string{"rate limit", "releases page"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
