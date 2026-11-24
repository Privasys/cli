// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"strings"
	"testing"
)

func teeJSON(digest string) string {
	return `{"Tee":{"name":"v","measurements":[{"Mrenclave":"aa"}],"attestation_servers":[],"required_oids":[{"oid":"` +
		OIDWorkloadImageDigest + `","value":"` + digest + `"}],"acceptable_tcb_statuses":null}}`
}

func policyJSON(owner, extra string, tees ...string) json.RawMessage {
	return json.RawMessage(`{"version":3,"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"` + owner + `"}},"tees":[` +
		strings.Join(tees, ",") + `]},"operations":[{"op":"Unwrap","principals":["AnyTee"]}]` + extra + `}`)
}

func TestCheckRetireChange(t *testing.T) {
	old, cur, third := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	current := policyJSON("s", "", teeJSON(old), teeJSON(cur))

	// The exact retirement passes, whatever its key order or spacing.
	ok := json.RawMessage(`{ "operations":[{"principals":["AnyTee"],"op":"Unwrap"}], "principals":{"tees":[` + teeJSON(cur) +
		`],"owner":{"Oidc":{"sub":"s","issuer":"https://privasys.id"}}}, "version":3 }`)
	if err := CheckRetireChange(current, ok, strings.ToUpper(old)); err != nil {
		t.Fatalf("the exact retirement was refused: %v", err)
	}

	refused := map[string]json.RawMessage{
		"a measurement added":   policyJSON("s", "", teeJSON(cur), teeJSON(third)),
		"the owner changed":     policyJSON("attacker", "", teeJSON(cur)),
		"an unknown field":      policyJSON("s", `,"approval":"none"`, teeJSON(cur)),
		"the other one retired": policyJSON("s", "", teeJSON(old)),
		"nothing retired":       current,
	}
	for name, proposed := range refused {
		if err := CheckRetireChange(current, proposed, old); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if err := CheckRetireChange(current, ok, third); err == nil || !strings.Contains(err.Error(), "no measurement") {
		t.Fatalf("a digest the policy lacks: %v", err)
	}
	if err := CheckRetireChange(policyJSON("s", "", teeJSON(old)), policyJSON("s", ""), old); err == nil {
		t.Fatal("the last measurement was retired")
	}
	// A rule naming a TEE by position would change meaning when one is removed.
	byIndex := json.RawMessage(strings.Replace(string(current), `["AnyTee"]`, `[{"Tee":1}]`, 1))
	if err := CheckRetireChange(byIndex, ok, old); err == nil {
		t.Fatal("a policy with a TEE index reference was accepted")
	}
}
