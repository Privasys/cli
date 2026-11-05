// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import "testing"

func TestConfigDescriptor(t *testing.T) {
	configTool := map[string]interface{}{"name": "configure", "role": "config", "endpoint": "/configure"}
	functions := []interface{}{map[string]interface{}{"name": "status", "role": "status"}, configTool}
	cases := []struct {
		name   string
		schema map[string]interface{}
		want   string
	}{
		{"section with a name", map[string]interface{}{"configure": map[string]interface{}{"name": "load_model", "endpoint": "/v1/models/load"}}, "load_model"},
		{"section with a function", map[string]interface{}{"configure": map[string]interface{}{"function": "setup"}}, "setup"},
		{"section with an endpoint", map[string]interface{}{"configure": map[string]interface{}{"endpoint": "/setup"}}, "setup"},
		{"section naming no target, and a config tool", map[string]interface{}{
			"configure": map[string]interface{}{"readiness_path": "/readiness"},
			"functions": functions,
		}, "configure"},
		{"only a config tool", map[string]interface{}{"functions": functions}, "configure"},
		{"section naming no target, and no config tool", map[string]interface{}{
			"configure": map[string]interface{}{"readiness_path": "/readiness"},
		}, ""},
		{"nothing declared", map[string]interface{}{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, fn := configDescriptor(c.schema)
			if name != c.want {
				t.Errorf("name = %q, want %q", name, c.want)
			}
			if (fn == nil) != (c.want == "") {
				t.Errorf("descriptor = %v for name %q", fn, name)
			}
		})
	}
}
