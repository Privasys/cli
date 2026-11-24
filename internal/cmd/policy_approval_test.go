// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

func TestPolicyApprovalFrom(t *testing.T) {
	body := `{"error":"x","code":"policy_approval_required","approval":{"operation":"update_policy","handle":"apps.privasys.org/a/data","policy_version":4,` +
		`"target":"ab","new_policy":{"b":1,"a":2},"audience":"privasys-platform-test","constellation_id":"c1","binding_version":2,"members":["m2","m1"]}}`
	pa, ok := api.PolicyApprovalFrom(&api.StatusError{Status: http.StatusPreconditionRequired, Body: []byte(body)})
	if !ok || pa.PolicyVersion != 4 || pa.ConstellationID != "c1" || len(pa.Members) != 2 {
		t.Fatalf("got %+v, %v", pa, ok)
	}
	// The policy bytes are kept exactly as sent.
	if string(pa.NewPolicy) != `{"b":1,"a":2}` {
		t.Fatalf("new_policy re-serialised: %s", pa.NewPolicy)
	}
	if _, ok := api.PolicyApprovalFrom(&api.StatusError{Status: http.StatusConflict, Body: []byte(body)}); ok {
		t.Fatal("a 409 was read as a 428")
	}
	if api.PolicyChangeCode(&api.StatusError{Status: 409, Body: []byte(`{"code":"policy_approval_stale"}`)}) != "policy_approval_stale" {
		t.Fatal("code not read")
	}
}

func TestCheckPolicyApproval(t *testing.T) {
	policy := json.RawMessage(`{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"s"}},"rules":[]}`)
	pd, err := vault.PolicyDigestJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	ok := func() *api.PolicyApproval {
		return &api.PolicyApproval{Operation: "update_policy", Handle: "h", PolicyVersion: 4, Target: pd,
			NewPolicy: policy, BindingVersion: 2, Members: []string{"m2", "m1"}}
	}
	members := []string{"m1", "m2"}
	if err := checkPolicyApproval(ok(), 2, members, 4); err != nil {
		t.Fatalf("a good request was refused: %v", err)
	}
	cases := map[string]func(*api.PolicyApproval) (int, []string, uint64){
		"other op":       func(p *api.PolicyApproval) (int, []string, uint64) { p.Operation = "export"; return 2, members, 4 },
		"vaults on v1":   func(*api.PolicyApproval) (int, []string, uint64) { return 1, members, 4 },
		"stale version":  func(*api.PolicyApproval) (int, []string, uint64) { return 2, members, 5 },
		"other members":  func(*api.PolicyApproval) (int, []string, uint64) { return 2, []string{"m1", "m3"}, 4 },
		"missing member": func(p *api.PolicyApproval) (int, []string, uint64) { p.Members = []string{"m1"}; return 2, members, 4 },
		"wrong target": func(p *api.PolicyApproval) (int, []string, uint64) {
			p.Target = strings.Repeat("0", 64)
			return 2, members, 4
		},
		"other policy": func(p *api.PolicyApproval) (int, []string, uint64) {
			p.NewPolicy = json.RawMessage(`{"rules":[1]}`)
			return 2, members, 4
		},
		"unreadable json": func(p *api.PolicyApproval) (int, []string, uint64) {
			p.NewPolicy = json.RawMessage(`{"a":1,"a":2}`)
			return 2, members, 4
		},
	}
	for name, mutate := range cases {
		p := ok()
		b, m, v := mutate(p)
		if err := checkPolicyApproval(p, b, m, v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
