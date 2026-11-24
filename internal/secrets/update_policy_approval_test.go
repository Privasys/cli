// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

func TestUpdatePolicyApproval(t *testing.T) {
	ids := []PinnedIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)}
	policy := json.RawMessage(`{"operations":[],"version":2}`)
	a, err := UpdatePolicyApproval("apps.privasys.org/x/data", 4, ids, policy, "aud", nil)
	if err != nil {
		t.Fatalf("a valid policy approval was refused: %v", err)
	}
	pd, _ := vault.PolicyDigestJSON(policy)
	if a.Target != pd || a.Operation != vault.BindUpdatePolicy || a.PolicyVersion != 4 {
		t.Fatalf("approval: %+v", a)
	}
	// The binding privasys.id returns for it is accepted.
	now := time.Now()
	ans, _ := json.Marshal(honestAnswer(t, a, now))
	if _, _, err := verifyApprovalV2(a, ans, now); err != nil {
		t.Fatalf("the honest binding was refused: %v", err)
	}
	if _, err := UpdatePolicyApproval("h", 4, ids, json.RawMessage(`{"a":1,"a":2}`), "aud", nil); err == nil {
		t.Fatal("an unreadable policy was accepted")
	}

	// Every member advertising update_policy_from: plain update_policy refused.
	from := make([]PinnedIdentity, len(ids))
	for i, id := range ids {
		id.id.Capabilities = []string{vault.CapabilityUpdatePolicyFrom}
		from[i] = id
	}
	if _, err := UpdatePolicyApproval("h", 4, from, policy, "aud", nil); err == nil {
		t.Fatal("update_policy was built for vaults that take update_policy_from")
	}
	// Only some members: still update_policy.
	if _, err := UpdatePolicyApproval("h", 4, []PinnedIdentity{from[0], ids[1]}, policy, "aud", nil); err != nil {
		t.Fatalf("mixed members: %v", err)
	}
}
