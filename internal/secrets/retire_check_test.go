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
}

// Rules naming TEEs by position follow the control plane's renumbering: above
// the retired one moves down, the retired one goes, an emptied rule goes.
func TestCheckRetireChangeRenumbers(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	pol := func(tees []string, rules string) json.RawMessage {
		return json.RawMessage(`{"version":3,"principals":{"owner":{"Oidc":{"issuer":"i","sub":"s"}},"tees":[` +
			strings.Join(tees, ",") + `]},"operations":[` + rules + `]}`)
	}
	current := pol([]string{teeJSON(a), teeJSON(b), teeJSON(c)},
		`{"ops":["Unwrap"],"principals":[{"Tee":0},{"Tee":2}]},`+
			`{"ops":["Export"],"principals":[{"Tee":1}]},`+
			`{"ops":["Wrap"],"principals":["Owner",{"Tee":1}]}`)
	// Retiring b (index 1): Tee 2 becomes 1, the Export rule (only b) goes,
	// the Wrap rule keeps Owner.
	want := pol([]string{teeJSON(a), teeJSON(c)},
		`{"ops":["Unwrap"],"principals":[{"Tee":0},{"Tee":1}]},`+
			`{"ops":["Wrap"],"principals":["Owner"]}`)
	if err := CheckRetireChange(current, want, b); err != nil {
		t.Fatalf("the renumbered retirement was refused: %v", err)
	}
	refused := map[string]json.RawMessage{
		"no renumbering": pol([]string{teeJSON(a), teeJSON(c)},
			`{"ops":["Unwrap"],"principals":[{"Tee":0},{"Tee":2}]},{"ops":["Wrap"],"principals":["Owner"]}`),
		"a right moved to another build": pol([]string{teeJSON(a), teeJSON(c)},
			`{"ops":["Unwrap"],"principals":[{"Tee":0},{"Tee":1}]},{"ops":["Export"],"principals":[{"Tee":1}]},{"ops":["Wrap"],"principals":["Owner"]}`),
		"the emptied rule kept": pol([]string{teeJSON(a), teeJSON(c)},
			`{"ops":["Unwrap"],"principals":[{"Tee":0},{"Tee":1}]},{"ops":["Export"],"principals":[]},{"ops":["Wrap"],"principals":["Owner"]}`),
	}
	for name, proposed := range refused {
		if err := CheckRetireChange(current, proposed, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A TEE index anywhere but a rule's principals is refused.
	odd := json.RawMessage(strings.Replace(string(current), `"ops":["Export"]`, `"ops":["Export"],"requires":[{"Tee":1}]`, 1))
	if err := CheckRetireChange(odd, want, b); err == nil || !strings.Contains(err.Error(), "outside its operation rules") {
		t.Fatalf("an index outside the rules: %v", err)
	}
}
