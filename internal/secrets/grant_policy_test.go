// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func fakeGrant(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestGrantPolicy(t *testing.T) {
	policy := map[string]interface{}{"principals": map[string]interface{}{
		"owner": map[string]interface{}{"Oidc": map[string]interface{}{"issuer": "https://privasys.id", "sub": "me"}}}}
	p, err := GrantPolicy(fakeGrant(t, map[string]interface{}{"sub": "me", "policy": policy}), "me")
	if err != nil || len(p) == 0 {
		t.Fatalf("a good grant: %v", err)
	}
	other := map[string]interface{}{"principals": map[string]interface{}{
		"owner": map[string]interface{}{"Oidc": map[string]interface{}{"sub": "attacker"}}}}
	for name, g := range map[string]string{
		"another sub":           fakeGrant(t, map[string]interface{}{"sub": "attacker", "policy": policy}),
		"policy owned by other": fakeGrant(t, map[string]interface{}{"sub": "me", "policy": other}),
		"no policy":             fakeGrant(t, map[string]interface{}{"sub": "me"}),
		"not a JWT":             "abc",
		"bad payload":           "e30.%%%.sig",
	} {
		if _, err := GrantPolicy(g, "me"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := GrantPolicy(fakeGrant(t, map[string]interface{}{"sub": "", "policy": policy}), ""); err == nil {
		t.Error("an empty caller was accepted")
	}
}
