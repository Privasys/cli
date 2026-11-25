// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every tool is classified, with a title, and the hints agree with what the
// tool says it does. A new tool fails here until it is added to toolHints.
func TestToolAnnotations(t *testing.T) {
	srv := NewServer(nil, "test")
	names := map[string]bool{}
	for _, tl := range srv.tools {
		names[tl.Name] = true
		h, ok := toolHints[tl.Name]
		if !ok {
			t.Errorf("%s: not in toolHints (add its title and hints)", tl.Name)
			continue
		}
		if strings.TrimSpace(h.title) == "" {
			t.Errorf("%s: no title", tl.Name)
		}
		if h.readOnly && h.destructive {
			t.Errorf("%s: read-only and destructive", tl.Name)
		}
		if h.readOnly && !h.idempotent {
			t.Errorf("%s: read-only but not idempotent", tl.Name)
		}
		d := strings.ToUpper(tl.Description)
		if strings.Contains(d, "DESTRUCTIVE") && !h.destructive {
			t.Errorf("%s: says DESTRUCTIVE but is not marked so", tl.Name)
		}
		if strings.Contains(d, "DANGEROUS") && h.readOnly {
			t.Errorf("%s: says DANGEROUS but is marked read-only", tl.Name)
		}
		for _, verb := range []string{"_delete", "_rm", "_remove", "_revoke", "_retire", "_stop"} {
			if strings.Contains(tl.Name+"_", verb+"_") && !h.destructive {
				t.Errorf("%s: a %s tool not marked destructive", tl.Name, verb)
			}
		}
	}
	for name := range toolHints {
		if !names[name] {
			t.Errorf("toolHints has %s, which is not a tool", name)
		}
	}
}

// tools/list carries the title and all four hints, explicitly.
func TestToolListAnnotations(t *testing.T) {
	for _, tl := range NewServer(nil, "test").toolList() {
		a, _ := tl["annotations"].(map[string]interface{})
		for _, k := range []string{"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
			if _, ok := a[k]; !ok {
				t.Errorf("%v: annotations lack %s", tl["name"], k)
			}
		}
		if tl["title"] == nil {
			t.Errorf("%v: no top-level title", tl["name"])
		}
	}
	if a := annotationsFor("no_such_tool"); a["destructiveHint"] != true || a["readOnlyHint"] != false {
		t.Errorf("an unclassified tool is not given the cautious defaults: %v", a)
	}
}

func TestNegotiateVersion(t *testing.T) {
	for asked, want := range map[string]string{
		"2025-06-18": "2025-06-18", "2025-03-26": "2025-03-26", "2024-11-05": "2024-11-05",
		"2099-01-01": protocolVersion, "": protocolVersion,
	} {
		p, _ := json.Marshal(map[string]string{"protocolVersion": asked})
		if got := negotiateVersion(p); got != want {
			t.Errorf("asked %q: got %q, want %q", asked, got, want)
		}
	}
	if negotiateVersion(nil) != protocolVersion {
		t.Error("no params")
	}
}
