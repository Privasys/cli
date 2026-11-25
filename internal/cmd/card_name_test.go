// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import "testing"

func TestWithCardNameKeepsTheSummary(t *testing.T) {
	in := map[string]string{"summary": "Create a new key under a deleted name: vaults/v/k/new-2"}
	got := withCardName(in, "key k in vault v")
	if got["app_name"] != "key k in vault v" || got["summary"] != in["summary"] {
		t.Fatalf("got %v", got)
	}
	if _, touched := in["app_name"]; touched {
		t.Error("the caller's map was changed")
	}
	if got := withCardName(nil, "secret s"); got["app_name"] != "secret s" {
		t.Errorf("nil context: %v", got)
	}
	if got := withCardName(map[string]string{"app_name": "kept"}, ""); got["app_name"] != "kept" {
		t.Errorf("an empty name replaced the existing one: %v", got)
	}
}
