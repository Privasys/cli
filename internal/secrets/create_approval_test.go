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

// A create approval for a re-created name binds the stored-form policy at
// version 0, with the target computed from it.
func TestCreateApproval(t *testing.T) {
	ids := []PinnedIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)}
	policy := json.RawMessage(`{"version":0,"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"s"}}},"operations":[]}`)
	h := "vaults/6f186e39-cbf7-4d9c-9f7c-1059d41227bc/card1/new-2"
	a, err := CreateApproval(h, policy, ids, "aud", nil)
	if err != nil {
		t.Fatal(err)
	}
	pd, _ := vault.PolicyDigestJSON(policy)
	if a.Operation != vault.BindCreate || a.Target != pd || a.PolicyVersion != 0 || a.Handle != h {
		t.Fatalf("approval: %+v", a)
	}
	now := time.Now()
	ans, _ := json.Marshal(honestAnswer(t, a, now))
	if _, _, err := verifyApprovalV2(a, ans, now); err != nil {
		t.Fatalf("the honest binding was refused: %v", err)
	}
	for name, mutate := range map[string]func(*ApprovalV2){
		"no policy":      func(x *ApprovalV2) { x.NewPolicy = nil },
		"version 1":      func(x *ApprovalV2) { x.PolicyVersion = 1 },
		"another target": func(x *ApprovalV2) { x.Target = strings.Repeat("0", 64) },
		"current policy": func(x *ApprovalV2) { x.CurrentPolicy = policy },
		"duplicate keys": func(x *ApprovalV2) { x.NewPolicy = json.RawMessage(`{"a":1,"a":2}`) },
	} {
		b := a
		mutate(&b)
		if b.check() == nil {
			t.Errorf("%s: passed", name)
		}
	}
}
