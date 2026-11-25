// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

func member(t *testing.T, ep string, v uint32, raw json.RawMessage) MemberPolicy {
	t.Helper()
	pd, err := vault.PolicyDigestJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return MemberPolicy{Endpoint: ep, Raw: raw, Version: v, PD: pd}
}

func TestPlanDirectChange(t *testing.T) {
	p := func(m, r1, r2 string) string { return tdxTee("", m, r1, r2) }
	o := pol([]string{p("f2", "e0", "4a"), p("f2", "cd", "5d")}, "")
	other := pol([]string{p("f2", "aa", "bb"), p("f2", "cd", "5d")}, "")
	retire := func(cur json.RawMessage) (json.RawMessage, error) {
		return ExpectRetireRuntime(cur, Runtime{"f2", "e0", "4a"})
	}
	tgt, _ := retire(o)

	// All agree: every member moves.
	pl, err := PlanDirectChange(bg, []MemberPolicy{member(t, "v1", 4, o), member(t, "v2", 4, o)}, retire, identityCanon)
	if err != nil || len(pl.ToUpdate) != 2 || len(pl.Done) != 0 || pl.Version != 4 {
		t.Fatalf("agreeing: %+v %v", pl, err)
	}
	// An interrupted run: v2 already holds the target, so only v1 moves.
	pl, err = PlanDirectChange(bg, []MemberPolicy{member(t, "v1", 4, o), member(t, "v2", 5, tgt)}, retire, identityCanon)
	if err != nil || len(pl.ToUpdate) != 1 || pl.ToUpdate[0] != "v1" || pl.Done[0] != "v2" {
		t.Fatalf("partial: %+v %v", pl, err)
	}
	// The same, listed the other way round.
	pl, err = PlanDirectChange(bg, []MemberPolicy{member(t, "v2", 5, tgt), member(t, "v1", 4, o)}, retire, identityCanon)
	if err != nil || len(pl.ToUpdate) != 1 || pl.ToUpdate[0] != "v1" {
		t.Fatalf("partial, reversed: %+v %v", pl, err)
	}
	// Done everywhere: nothing to update.
	arm := func(cur json.RawMessage) (json.RawMessage, error) { return ExpectTCBPolicy(cur, []string{"X"}) }
	armed, _ := arm(o)
	pl, err = PlanDirectChange(bg, []MemberPolicy{member(t, "v1", 5, armed), member(t, "v2", 5, armed)}, arm, identityCanon)
	if err != nil || len(pl.ToUpdate) != 0 || len(pl.Done) != 2 {
		t.Fatalf("done: %+v %v", pl, err)
	}
	// A split that no single change explains is refused, naming each member.
	_, err = PlanDirectChange(bg, []MemberPolicy{member(t, "v1", 4, o), member(t, "v2", 4, other)}, retire, identityCanon)
	if err == nil || !strings.Contains(err.Error(), "v1 v4") || !strings.Contains(err.Error(), "v2 v4") {
		t.Fatalf("unexplained split: %v", err)
	}
	// The same policy at two versions is refused.
	if _, err := PlanDirectChange(bg, []MemberPolicy{member(t, "v1", 4, o), member(t, "v2", 5, o)}, retire, identityCanon); err == nil {
		t.Fatal("same policy, different versions, accepted")
	}
}
