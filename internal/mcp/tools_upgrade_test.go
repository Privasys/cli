// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import "testing"

// TestArgStrSlice covers the array argument that carries attest's
// --allowed-platform pins over MCP (clients send []interface{}).
func TestArgStrSlice(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want []string
	}{
		{"json array", map[string]interface{}{"p": []interface{}{"aa", "bb"}}, []string{"aa", "bb"}},
		{"single string tolerated", map[string]interface{}{"p": "aa"}, []string{"aa"}},
		{"empties dropped", map[string]interface{}{"p": []interface{}{"aa", "", 7}}, []string{"aa"}},
		{"missing", map[string]interface{}{}, nil},
		{"empty string", map[string]interface{}{"p": ""}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := argStrSlice(c.args, "p")
			if len(got) != len(c.want) {
				t.Fatalf("argStrSlice = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("argStrSlice = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// TestUpgradeToolsAreTwoPhase locks the consent contract: the guided upgrade
// tools must expose a 'confirm' flag, and must not promote without it.
func TestUpgradeToolsAreTwoPhase(t *testing.T) {
	for _, tl := range upgradeTools() {
		props, _ := tl.Schema["properties"].(map[string]interface{})
		if _, ok := props["confirm"]; !ok {
			t.Errorf("%s: missing the 'confirm' consent flag", tl.Name)
		}
		for _, req := range tl.Schema["required"].([]string) {
			if req == "confirm" {
				t.Errorf("%s: 'confirm' must NOT be required — the first call reviews without promoting", tl.Name)
			}
		}
	}
}
