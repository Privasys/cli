package cmd

import "testing"

func TestResolveContainerPath(t *testing.T) {
	app := map[string]interface{}{
		"container_mcp": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "chat", "endpoint": "/v1/chat/completions"},
			},
			"configure": map[string]interface{}{
				"name":     "load_model",
				"endpoint": "/v1/models/load",
			},
		},
	}
	cases := map[string]string{
		"chat":           "/v1/chat/completions", // a declared tool
		"load_model":     "/v1/models/load",      // the configure section, by its name
		"v1/models/load": "/v1/models/load",      // the configure section, named after its endpoint
		"health":         "/health",              // undeclared: the function is the path
	}
	for fn, want := range cases {
		if got := resolveContainerPath(app, fn); got != want {
			t.Errorf("resolveContainerPath(%q) = %q, want %q", fn, got, want)
		}
	}
	if got := resolveContainerPath(map[string]interface{}{}, "configure"); got != "/configure" {
		t.Errorf("no manifest: got %q, want /configure", got)
	}
}
