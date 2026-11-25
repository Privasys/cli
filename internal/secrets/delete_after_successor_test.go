// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// A delete_after whose successor exists: alone, target computed from the
// successor, at most 600 s, never its own successor, never batched.
func TestDeleteAfterSuccessorApproval(t *testing.T) {
	ids := []PinnedIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)}
	old, next := "apps.privasys.org/x/storage-kek/v1", "apps.privasys.org/x/storage-kek/v2"
	a, err := DeleteAfterSuccessorApproval(old, next, 3, ids, "aud", nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := vault.DeleteAfterTarget(next, "-")
	if a.Target != want || a.SuccessorHandle != next || a.maxLeft() != singleBeginTTL {
		t.Fatalf("approval: %+v", a)
	}
	// Wallet's cross-checked digest for successor "apps/x/data-v2", no target.
	if d, _ := vault.DeleteAfterTarget("apps/x/data-v2", "-"); d != "987995df9ada8009cf264cedcede390f35dacee52c74049855eaa2a2a8447727" {
		t.Fatalf("delete_after target %s", d)
	}
	now := time.Now()
	ans, _ := json.Marshal(honestAnswer(t, a, now))
	if _, _, err := verifyApprovalV2(a, ans, now); err != nil {
		t.Fatalf("the honest binding was refused: %v", err)
	}

	if _, err := DeleteAfterSuccessorApproval(old, old, 3, ids, "aud", nil); err == nil {
		t.Fatal("a key was its own successor")
	}
	long := a
	long.TTLSeconds = 601
	if long.check() == nil {
		t.Fatal("a successor delete_after of 601 s passed")
	}
	stray := a
	stray.Target = strings.Repeat("0", 64)
	if stray.check() == nil {
		t.Fatal("a target not from the successor passed")
	}
	other := ApprovalV2{Operation: vault.BindExport, Handle: old, SuccessorHandle: next, Identities: ids}
	if other.check() == nil {
		t.Fatal("a successor on an export passed")
	}
	if _, err := BeginBatchV2(t.Context(), "http://127.0.0.1:1", "b", "l", "", []ApprovalV2{
		{Operation: vault.BindPromote, Handle: next, Target: strings.Repeat("1", 64), Identities: ids}, a,
	}); err == nil || !strings.Contains(err.Error(), "not in a batch") {
		t.Fatalf("a successor delete_after in a batch: %v", err)
	}
}
