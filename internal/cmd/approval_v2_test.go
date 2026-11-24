// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"io"
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/secrets"
)

// onV2 makes the keys in handles read as taking binding v2, for one test.
func onV2(t *testing.T, handles ...string) {
	t.Helper()
	v2 := map[string]bool{}
	for _, h := range handles {
		v2[h] = true
	}
	prev := readKeyApproval
	readKeyApproval = func(_ context.Context, _, _ string, tgt secrets.KeyTarget, op vault.Operation) (int, []secrets.PinnedIdentity, error) {
		if op != vault.OpPromoteProfile {
			t.Errorf("asked about %s on a promote", op)
		}
		if v2[tgt.Handle] {
			return 2, nil, nil
		}
		return 1, nil, nil
	}
	t.Cleanup(func() { readKeyApproval = prev })
}

func TestAKeyOnV2VaultsIsPreparedForV2(t *testing.T) {
	onV2(t, aHandle)
	f := newFakeRoll(t)
	client := api.New(f.srv.URL, "admin")
	targets, err := releaseTargets(context.Background(), client, "", "enc-1", "m1", "tdx-v9", nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]*approvalOp{}
	for _, tg := range targets {
		ops, err := tg.Prepare(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range ops {
			seen[op.Handle] = op
		}
	}
	a := seen[aHandle]
	if a == nil || a.V2 == nil {
		t.Fatalf("the v2 key was prepared for v1: %+v", a)
	}
	if a.V2.Operation != vault.BindPromote || a.V2.Handle != aHandle || a.V2.Target != a.MeasurementDigest ||
		a.V2.PolicyVersion != a.PolicyVersion || a.V2.Audience != a.Audience {
		t.Fatalf("the v2 approval does not bind the staged promote: %+v vs %+v", a.V2, a.BatchEntry)
	}
	for _, h := range []string{mgrHandle, bHandle, bCred} {
		if op := seen[h]; op != nil && op.V2 != nil {
			t.Errorf("%s was prepared for v2", h)
		}
	}
}

func TestV1AndV2AreApprovedSeparately(t *testing.T) {
	v1a := &approvalOp{BatchEntry: secrets.BatchEntry{Operation: "promote", Handle: "a"}, Audience: "aud"}
	v2b := &approvalOp{BatchEntry: secrets.BatchEntry{Operation: "promote", Handle: "b"}, Audience: "aud", V2: &secrets.ApprovalV2{}}
	v1c := &approvalOp{BatchEntry: secrets.BatchEntry{Operation: "promote", Handle: "c"}, Audience: "aud"}
	groups := groupByAudience([]*approvalOp{v1a, v2b, v1c})
	if len(groups) != 2 || len(groups[0]) != 2 || groups[0][1] != v1c || len(groups[1]) != 1 || !v2Group(groups[1]) || v2Group(groups[0]) {
		t.Fatalf("groups: %+v", groups)
	}
}
