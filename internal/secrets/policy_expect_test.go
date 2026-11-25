// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExpectTCBPolicy(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	current := policyJSON("s", "", teeJSON(a), teeJSON(b))
	got, err := ExpectTCBPolicy(current, []string{"ConfigurationAndSWHardeningNeeded"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got), `"acceptable_tcb_statuses":["ConfigurationAndSWHardeningNeeded"]`) != 2 {
		t.Fatalf("not every profile armed: %s", got)
	}
	strict, err := ExpectTCBPolicy(current, []string{})
	if err != nil || strings.Count(string(strict), `"acceptable_tcb_statuses":[]`) != 2 {
		t.Fatalf("strict: %s, %v", strict, err)
	}
	// Only the TCB sets change: everything else is the current policy.
	same, _ := SameStoredPolicy(bg, identityCanon, current, current)
	if !same {
		t.Fatal("identity comparison")
	}
	if s, _ := SameStoredPolicy(bg, identityCanon, got, current); s {
		t.Fatal("an armed policy compared equal to the unarmed one")
	}
	for name, st := range map[string][]string{"nil": nil, "revoked": {"Revoked"}} {
		if _, err := ExpectTCBPolicy(current, st); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ExpectTCBPolicy(json.RawMessage(`{"principals":{"tees":[]}}`), []string{}); err == nil {
		t.Error("a policy with no TEE profile was armed")
	}
	// A proposal that also adds a measurement is not the arming.
	extra := policyJSON("s", "", teeJSON(a), teeJSON(b), teeJSON(strings.Repeat("c", 64)))
	armedExtra, _ := ExpectTCBPolicy(extra, []string{"ConfigurationAndSWHardeningNeeded"})
	if s, _ := SameStoredPolicy(bg, identityCanon, got, armedExtra); s {
		t.Fatal("an arming that adds a measurement compared equal")
	}
}

func TestExpectAutoMigrate(t *testing.T) {
	current := json.RawMessage(`{"version":1,"lifecycle":{"ttl_seconds":7776000,"auto_migrate_to_next_attestation_profile":false},"operations":[]}`)
	on, err := ExpectAutoMigrate(current, true)
	if err != nil || !strings.Contains(string(on), `"auto_migrate_to_next_attestation_profile":true`) || !strings.Contains(string(on), `"ttl_seconds":7776000`) {
		t.Fatalf("on: %s, %v", on, err)
	}
	// No lifecycle yet: it is added.
	bare, err := ExpectAutoMigrate(json.RawMessage(`{"version":1}`), true)
	if err != nil || !strings.Contains(string(bare), `"auto_migrate_to_next_attestation_profile":true`) {
		t.Fatalf("bare: %s, %v", bare, err)
	}
	if _, err := ExpectAutoMigrate(json.RawMessage(`[1]`), true); err == nil {
		t.Error("a non-object policy was accepted")
	}
}
