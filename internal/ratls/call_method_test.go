// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import "testing"

func TestConfigureEndpoint(t *testing.T) {
	app := map[string]interface{}{"container_mcp": map[string]interface{}{
		"configure": map[string]interface{}{"name": "configure", "endpoint": "/configure"}}}
	if got := ConfigureEndpoint(app); got != "/configure" {
		t.Fatalf("got %q", got)
	}
	if got := ConfigureEndpoint(map[string]interface{}{}); got != "" {
		t.Fatalf("no manifest: got %q", got)
	}
}

func TestCallMethod(t *testing.T) {
	body := []byte(`{"a":1}`)
	cases := []struct {
		name, method, path, cfg string
		body                    []byte
		want                    string
		fail                    bool
	}{
		{"default POST", "", "/run", "/configure", nil, "POST", false},
		{"default POST with data", "", "/configure", "/configure", body, "POST", false},
		{"empty POST to configure refused", "", "/configure", "/configure", nil, "", true},
		{"trailing slash and query still configure", "", "/configure/?x=1", "/configure", nil, "", true},
		{"no leading slash still configure", "", "configure", "/configure", nil, "", true},
		{"no declared configure", "", "/configure", "", nil, "POST", false},
		{"explicit GET reads configure", "get", "/configure", "/configure", nil, "GET", false},
		{"explicit POST empty on purpose", "POST", "/configure", "/configure", nil, "POST", false},
		{"GET with a body refused", "GET", "/x", "", body, "", true},
		{"HEAD with a body refused", "HEAD", "/x", "", body, "", true},
		{"PUT", "put", "/x", "", body, "PUT", false},
		{"DELETE", "DELETE", "/x", "", nil, "DELETE", false},
		{"unknown method", "TRACE", "/x", "", nil, "", true},
		{"other path empty POST", "", "/configure2", "/configure", nil, "POST", false},
	}
	for _, c := range cases {
		got, err := CallMethod(c.method, c.body, c.path, c.cfg)
		if c.fail {
			if err == nil {
				t.Errorf("%s: want an error, got %q", c.name, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}
