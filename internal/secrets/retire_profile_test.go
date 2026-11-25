// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"strings"
	"testing"
)

func tdxTee(digest, mrtd, r1, r2 string) string {
	return `{"Tee":{"name":"v","measurements":[{"Tdx":{"mrtd":"` + mrtd + `","rtmr1":"` + r1 + `","rtmr2":"` + r2 + `"}}],"attestation_servers":[],` +
		`"required_oids":[{"oid":"` + OIDWorkloadImageDigest + `","value":"` + digest + `"}],"acceptable_tcb_statuses":null}}`
}

func pol(tees []string, rules string) json.RawMessage {
	return json.RawMessage(`{"version":3,"principals":{"owner":{"Oidc":{"issuer":"i","sub":"s"}},"tees":[` +
		strings.Join(tees, ",") + `]},"operations":[` + rules + `]}`)
}

// Image mode removes EVERY profile of the build, renumbering across all the
// removed positions.
func TestExpectRetireRemovesEveryProfile(t *testing.T) {
	old, cur := strings.Repeat("a", 64), strings.Repeat("b", 64)
	// tees: 0 old/rt1, 1 cur/rt1, 2 old/rt2, 3 cur/rt2
	current := pol([]string{tdxTee(old, "11", "12", "13"), tdxTee(cur, "11", "12", "13"), tdxTee(old, "21", "22", "23"), tdxTee(cur, "21", "22", "23")},
		`{"ops":["Unwrap"],"principals":[{"Tee":1},{"Tee":3}]},{"ops":["Export"],"principals":[{"Tee":0},{"Tee":2}]}`)
	want := pol([]string{tdxTee(cur, "11", "12", "13"), tdxTee(cur, "21", "22", "23")},
		`{"ops":["Unwrap"],"principals":[{"Tee":0},{"Tee":1}]}`)
	got, err := ExpectRetire(current, old)
	if err != nil {
		t.Fatal(err)
	}
	if same, _ := SameStoredPolicy(bg, identityCanon, got, want); !same {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	// Retiring the only build left is refused.
	if _, err := ExpectRetire(pol([]string{tdxTee(old, "1", "2", "3"), tdxTee(old, "4", "5", "6")}, ""), old); err == nil {
		t.Fatal("every profile retired")
	}
}

// Profile mode removes exactly the profile all four values name.
func TestExpectRetireProfile(t *testing.T) {
	cur := strings.Repeat("b", 64)
	current := pol([]string{tdxTee(cur, "AA", "bb", "cc"), tdxTee(cur, "dd", "ee", "ff")},
		`{"ops":["Unwrap"],"principals":["AnyTee"]},{"ops":["Export"],"principals":[{"Tee":1}]}`)
	got, err := ExpectRetireProfile(current, RetiredProfile{WorkloadDigest: strings.ToUpper(cur), MRTD: "aa", RTMR1: "BB", RTMR2: "cc"})
	if err != nil {
		t.Fatal(err)
	}
	want := pol([]string{tdxTee(cur, "dd", "ee", "ff")},
		`{"ops":["Unwrap"],"principals":["AnyTee"]},{"ops":["Export"],"principals":[{"Tee":0}]}`)
	if same, _ := SameStoredPolicy(bg, identityCanon, got, want); !same {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	for name, p := range map[string]RetiredProfile{
		"another runtime": {cur, "aa", "bb", "zz"},
		"another build":   {strings.Repeat("c", 64), "aa", "bb", "cc"},
		"incomplete":      {cur, "aa", "", "cc"},
	} {
		if _, err := ExpectRetireProfile(current, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := pol([]string{tdxTee(cur, "aa", "bb", "cc"), tdxTee(cur, "aa", "bb", "cc"), tdxTee(cur, "dd", "ee", "ff")}, "")
	if _, err := ExpectRetireProfile(dup, RetiredProfile{cur, "aa", "bb", "cc"}); err == nil || !strings.Contains(err.Error(), "identical") {
		t.Fatalf("duplicates: %v", err)
	}
	if _, err := ExpectRetireProfile(pol([]string{tdxTee(cur, "aa", "bb", "cc")}, ""), RetiredProfile{cur, "aa", "bb", "cc"}); err == nil {
		t.Fatal("the last profile was retired")
	}
}
