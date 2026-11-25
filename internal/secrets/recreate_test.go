// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"strings"
	"testing"
)

func TestReCreateApprovalGuards(t *testing.T) {
	v := "6f186e39-cbf7-4d9c-9f7c-1059d41227bc"
	b := "vaults/" + v + "/card1"
	// An ordinary name needs no approval.
	if tok, m, err := reCreateApproval(bg, VaultCreateParams{}, VaultAddressing{Handle: b}, "g"); err != nil || tok != "" || m != nil {
		t.Fatalf("ordinary name: %q %v %v", tok, m, err)
	}
	// A re-created name without an approver is refused before anything is sent.
	if _, _, err := reCreateApproval(bg, VaultCreateParams{}, VaultAddressing{Handle: b + "/new-2"}, "g"); err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("no approver: %v", err)
	}
	// Nothing but a renewal is created beneath a re-created name.
	if _, _, err := reCreateApproval(bg, VaultCreateParams{}, VaultAddressing{Handle: b + "/new-2/v2"}, "g"); err == nil {
		t.Fatal("a rotation beneath a re-created name was allowed")
	}
}

func TestCheckReCreatedNameShortCircuits(t *testing.T) {
	v, n := "6f186e39-cbf7-4d9c-9f7c-1059d41227bc", "card1"
	b := "vaults/" + v + "/" + n
	for _, h := range []string{b, b + "/v2", b + "/gen-3"} {
		if err := CheckReCreatedName(bg, nil, "", "", v, n, h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	if err := CheckReCreatedName(bg, nil, "", "", v, n, b+"/new-2/gen-2"); err == nil {
		t.Error("a renewal beneath a re-created name passed unchecked")
	}
	if err := CheckReCreatedName(bg, nil, "", "", v, n, b+"/new-1"); err == nil {
		t.Error("new-1 passed")
	}
}
