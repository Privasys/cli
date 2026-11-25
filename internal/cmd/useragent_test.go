// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestUserAgentOnEveryRequest(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	saved := http.DefaultTransport
	defer func() { http.DefaultTransport = saved }()
	installUserAgent()
	installUserAgent() // idempotent: no double wrapping

	if _, err := http.Get(srv.URL); err != nil { // the default client
		t.Fatal(err)
	}
	if _, err := (&http.Client{}).Get(srv.URL); err != nil { // a client with no transport of its own
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "explicit/1")
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("User-Agent") != "explicit/1" {
		t.Error("the caller's request was changed")
	}
	want := "privasys/" + Version + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"
	if len(got) != 3 || got[0] != want || got[1] != want || got[2] != "explicit/1" {
		t.Fatalf("user agents %q, want %q twice then the explicit one", got, want)
	}
	if !strings.HasPrefix(want, "privasys/") {
		t.Fatal(want)
	}
}
