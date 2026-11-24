// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import "testing"

func TestCheckVaultKeyHandle(t *testing.T) {
	v, n := "6f186e39-cbf7-4d9c-9f7c-1059d41227bc", "card1"
	b := "vaults/" + v + "/" + n
	for _, ok := range []string{b, b + "/v2", b + "/new-2", b + "/new-2/gen-5", b + "/gen-2", b + "/v3/gen-2"} {
		if err := CheckVaultKeyHandle(v, n, ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"vaults/" + v + "/card2",      // another key
		"vaults/" + v + "/card10",     // a name sharing the prefix
		"vaults/other/" + n,           // another vault
		b + "/new-1", b + "/v2/new-2", // new-1, new- not first
		b + "/new-3/v4",                   // a rotation under a re-created name
		b + "/v2/v3", b + "/x", b + "/v0", // twice, unknown, zero
		b + "/v02", b + "/gen-", b + "/", // non-canonical, empty
		"users/s/" + n,
	} {
		if err := CheckVaultKeyHandle(v, n, bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if CheckVaultKeyHandle(v, "a/b", "vaults/"+v+"/a/b") == nil {
		t.Error("a name with a slash was accepted")
	}
}
