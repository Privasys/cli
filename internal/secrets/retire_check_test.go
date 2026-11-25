// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/json"
	"errors"
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
	if err := CheckRetireChange(bg, current, ok, strings.ToUpper(old), identityCanon); err != nil {
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
		if err := CheckRetireChange(bg, current, proposed, old, identityCanon); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if err := CheckRetireChange(bg, current, ok, third, identityCanon); err == nil || !strings.Contains(err.Error(), "no measurement") {
		t.Fatalf("a digest the policy lacks: %v", err)
	}
	if err := CheckRetireChange(bg, policyJSON("s", "", teeJSON(old)), policyJSON("s", ""), old, identityCanon); err == nil {
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
	if err := CheckRetireChange(bg, current, want, b, identityCanon); err != nil {
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
		if err := CheckRetireChange(bg, current, proposed, b, identityCanon); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A TEE index anywhere but a rule's principals is refused.
	odd := json.RawMessage(strings.Replace(string(current), `"ops":["Export"]`, `"ops":["Export"],"requires":[{"Tee":1}]`, 1))
	if err := CheckRetireChange(bg, odd, want, b, identityCanon); err == nil || !strings.Contains(err.Error(), "outside its operation rules") {
		t.Fatalf("an index outside the rules: %v", err)
	}
}

var bg = context.Background()

// identityCanon is a vault that stores a policy exactly as given.
func identityCanon(_ context.Context, p json.RawMessage) (json.RawMessage, error) { return p, nil }

// defaultsCanon is a vault that writes its defaults out, as a real one does:
// every rule gets "requires": [], the principal set "auditors": [].
func defaultsCanon(_ context.Context, p json.RawMessage) (json.RawMessage, error) {
	doc, err := decodeTree(p)
	if err != nil {
		return nil, err
	}
	root := doc.(map[string]any)
	if pr, ok := root["principals"].(map[string]any); ok {
		if _, has := pr["auditors"]; !has {
			pr["auditors"] = []any{}
		}
	}
	if ops, ok := root["operations"].([]any); ok {
		for _, r := range ops {
			if rule, ok := r.(map[string]any); ok {
				if _, has := rule["requires"]; !has {
					rule["requires"] = []any{}
				}
			}
		}
	}
	return json.Marshal(root)
}

// The stored policy has every default written; the control plane's proposal
// leaves them out. Only the vault's canonicalisation makes them comparable.
func TestCheckRetireChangeStoredDefaults(t *testing.T) {
	old, cur := strings.Repeat("a", 64), strings.Repeat("b", 64)
	stored := json.RawMessage(`{"version":3,"principals":{"owner":{"Oidc":{"issuer":"i","sub":"s"}},"auditors":[],"tees":[` +
		teeJSON(old) + `,` + teeJSON(cur) + `]},"operations":[{"ops":["Unwrap"],"principals":["AnyTee"],"requires":[]}]}`)
	typed := json.RawMessage(`{"version":3,"principals":{"owner":{"Oidc":{"issuer":"i","sub":"s"}},"tees":[` +
		teeJSON(cur) + `]},"operations":[{"ops":["Unwrap"],"principals":["AnyTee"]}]}`)
	if err := CheckRetireChange(bg, stored, typed, old, identityCanon); err == nil {
		t.Fatal("without canonicalisation the defaults should differ (the bug this guards)")
	}
	if err := CheckRetireChange(bg, stored, typed, old, defaultsCanon); err != nil {
		t.Fatalf("an honest retire with stored defaults was refused: %v", err)
	}
	// A non-default field dropped still differs after canonicalisation.
	stored2 := json.RawMessage(strings.Replace(string(stored), `"requires":[]`, `"requires":[{"OidcStepUp":{"binding":2}}]`, 1))
	if err := CheckRetireChange(bg, stored2, typed, old, defaultsCanon); err == nil {
		t.Fatal("a dropped step-up condition was accepted")
	}
	// A vault that refuses to canonicalise: refused.
	refusing := func(context.Context, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("unknown field")
	}
	if err := CheckRetireChange(bg, stored, typed, old, refusing); err == nil {
		t.Fatal("accepted without the vault's canonical form")
	}
	if err := CheckRetireChange(bg, stored, typed, old, nil); err == nil {
		t.Fatal("accepted with no canonicaliser")
	}
}

// A binding-2 update must carry the stored form; a typed form with defaults
// left out is refused before the tap.
func TestRequireStoredForm(t *testing.T) {
	stored := json.RawMessage(`{"version":3,"principals":{"auditors":[]},"operations":[{"ops":["Unwrap"],"principals":["AnyTee"],"requires":[]}]}`)
	typed := json.RawMessage(`{"version":3,"principals":{},"operations":[{"ops":["Unwrap"],"principals":["AnyTee"]}]}`)
	reordered := json.RawMessage(`{"operations":[{"requires":[],"principals":["AnyTee"],"ops":["Unwrap"]}],"principals":{"auditors":[]},"version":3}`)
	if err := RequireStoredForm(bg, defaultsCanon, stored); err != nil {
		t.Fatalf("the stored form was refused: %v", err)
	}
	if err := RequireStoredForm(bg, defaultsCanon, reordered); err != nil {
		t.Fatalf("key order mattered: %v", err)
	}
	if err := RequireStoredForm(bg, defaultsCanon, typed); err == nil {
		t.Fatal("a typed form with defaults left out was accepted")
	}
	if err := RequireStoredForm(bg, nil, stored); err == nil {
		t.Fatal("accepted with no canonicaliser")
	}
}
