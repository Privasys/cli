// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package agents

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMergeFreshClaude(t *testing.T) {
	h, ok := Lookup("claude")
	if !ok {
		t.Fatal("claude not in registry")
	}
	out, changed, err := h.Merge(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("fresh file should report changed")
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	servers, _ := root["mcpServers"].(map[string]any)
	priv, _ := servers["privasys"].(map[string]any)
	if priv["command"] != "privasys" {
		t.Fatalf("command = %v, want privasys", priv["command"])
	}
	if _, hasType := priv["type"]; hasType {
		t.Fatal("claude entry should not carry a type field")
	}
}

func TestMergeVSCodeUsesServersAndStdio(t *testing.T) {
	h, _ := Lookup("vscode")
	out, _, err := h.Merge(nil)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	servers, ok := root["servers"].(map[string]any)
	if !ok {
		t.Fatalf("vscode should use the 'servers' key, got %v", root)
	}
	priv := servers["privasys"].(map[string]any)
	if priv["type"] != "stdio" {
		t.Fatalf("vscode entry type = %v, want stdio", priv["type"])
	}
}

func TestMergePreservesOtherServers(t *testing.T) {
	h, _ := Lookup("claude")
	existing := []byte(`{"mcpServers":{"other":{"command":"foo"}},"unrelated":42}`)
	out, changed, err := h.Merge(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("adding privasys should report changed")
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	servers := root["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Fatal("existing 'other' server was dropped")
	}
	if _, ok := servers["privasys"]; !ok {
		t.Fatal("privasys server not added")
	}
	if root["unrelated"].(float64) != 42 {
		t.Fatal("unrelated top-level key was dropped")
	}
}

func TestMergeIdempotent(t *testing.T) {
	h, _ := Lookup("claude")
	first, _, err := h.Merge(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, changed, err := h.Merge(first)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("re-merging identical content should report no change")
	}
	if string(first) != string(second) {
		t.Fatal("merge is not stable")
	}
}

func TestMergeInvalidJSON(t *testing.T) {
	h, _ := Lookup("claude")
	if _, _, err := h.Merge([]byte("{not json")); err == nil {
		t.Fatal("expected error on invalid existing JSON")
	}
}

func TestAgentsMDInsertAndReplace(t *testing.T) {
	out, changed := MergeAgentsMD(nil)
	if !changed {
		t.Fatal("fresh AGENTS.md should change")
	}
	if !strings.Contains(string(out), agentsBegin) || !strings.Contains(string(out), agentsEnd) {
		t.Fatal("managed markers missing")
	}

	// Re-running is a no-op.
	again, changed := MergeAgentsMD(out)
	if changed {
		t.Fatal("identical AGENTS.md should not change")
	}
	if string(again) != string(out) {
		t.Fatal("AGENTS.md not stable across runs")
	}

	// Existing user content is preserved, exactly one managed block remains.
	user := []byte("# My project\n\nSome rules.\n")
	merged, changed := MergeAgentsMD(user)
	if !changed {
		t.Fatal("appending to user file should change")
	}
	if !strings.Contains(string(merged), "Some rules.") {
		t.Fatal("user content lost")
	}
	if strings.Count(string(merged), agentsBegin) != 1 {
		t.Fatalf("want exactly one managed block, got %d", strings.Count(string(merged), agentsBegin))
	}
	// And a second pass still leaves exactly one block (replace in place).
	merged2, _ := MergeAgentsMD(merged)
	if strings.Count(string(merged2), agentsBegin) != 1 {
		t.Fatal("replace-in-place left duplicate blocks")
	}
}

func TestNamesSorted(t *testing.T) {
	names := Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Names() not sorted: %v", names)
		}
	}
}
