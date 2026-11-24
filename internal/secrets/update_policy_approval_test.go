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
	current := json.RawMessage(`{"operations":[],"version":1,"requires":[]}`)
	a, err := UpdatePolicyApproval("apps.privasys.org/x/data", 4, ids, policy, current, "aud", nil)
	if err != nil {
		t.Fatalf("a valid policy approval was refused: %v", err)
	}
	pd, _ := vault.PolicyDigestJSON(policy)
	if a.Target != pd || a.Operation != vault.BindUpdatePolicy || a.PolicyVersion != 4 || len(a.CurrentPolicy) != 0 {
		t.Fatalf("approval: %+v", a)
	}
	// The binding privasys.id returns for it is accepted.
	now := time.Now()
	ans, _ := json.Marshal(honestAnswer(t, a, now))
	if _, _, err := verifyApprovalV2(a, ans, now); err != nil {
		t.Fatalf("the honest binding was refused: %v", err)
	}
	if _, err := UpdatePolicyApproval("h", 4, ids, json.RawMessage(`{"a":1,"a":2}`), current, "aud", nil); err == nil {
		t.Fatal("an unreadable policy was accepted")
	}

	// Every member advertising update_policy_from: that form, binding both.
	from := make([]PinnedIdentity, len(ids))
	for i, id := range ids {
		id.id.Capabilities = []string{vault.CapabilityUpdatePolicyFrom}
		from[i] = id
	}
	f, err := UpdatePolicyApproval("h", 4, from, policy, current, "aud", nil)
	if err != nil {
		t.Fatalf("update_policy_from: %v", err)
	}
	curPD, _ := vault.PolicyDigestJSON(current)
	want, _ := vault.UpdatePolicyFromTarget(curPD, pd)
	if f.Operation != vault.BindUpdatePolicyFrom || f.Target != want || string(f.CurrentPolicy) != string(current) {
		t.Fatalf("update_policy_from approval: %+v", f)
	}
	ans, _ = json.Marshal(honestAnswer(t, f, now))
	if _, _, err := verifyApprovalV2(f, ans, now); err != nil {
		t.Fatalf("the honest update_policy_from binding was refused: %v", err)
	}
	if _, err := UpdatePolicyApproval("h", 4, from, policy, nil, "aud", nil); err == nil {
		t.Fatal("update_policy_from without the current policy was built")
	}
	// Only some members: update_policy.
	if m, err := UpdatePolicyApproval("h", 4, []PinnedIdentity{from[0], ids[1]}, policy, current, "aud", nil); err != nil || m.Operation != vault.BindUpdatePolicy {
		t.Fatalf("mixed members: %+v, %v", m.Operation, err)
	}

	// check() refuses a target not computed from the policies it carries.
	bad := f
	bad.Target = pd
	if bad.check() == nil {
		t.Fatal("an update_policy_from with the update_policy target passed")
	}
	stray := a
	stray.CurrentPolicy = current
	if stray.check() == nil {
		t.Fatal("an update_policy carrying a current policy passed")
	}
}
