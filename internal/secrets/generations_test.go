// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import "testing"

func TestGenerations(t *testing.T) {
	base := "users/sub-1/db"
	for handle, want := range map[string]int{
		base:                  1,
		base + "/v2":          2,
		base + "/v17":         17,
		base + "/v1":          0, // generation 1 is the bare name
		base + "/v0":          0,
		base + "/v02":         0,
		base + "/vx":          0,
		base + "/v2/v3":       0,
		base + "x/v2":         0, // another secret whose name starts the same
		"users/sub-1/db2":     0,
		"users/sub-2/db/v2":   0,
		base + "/v2" + "\n":   0,
		base + "/v9999999999": 0, // beyond an int on some platforms: refused, not wrapped
	} {
		if got := generationOf(base, handle); got != want {
			t.Errorf("generationOf(%q) = %d, want %d", handle, got, want)
		}
	}
	if GenerationHandle(base, 1) != base || GenerationHandle(base, 3) != base+"/v3" {
		t.Error("generation handles")
	}
	for _, bad := range []string{"users/s/x/v2", "users/s/v10"} {
		if checkSecretName(bad) == nil {
			t.Errorf("%s was accepted as a new secret's name", bad)
		}
	}
	for _, ok := range []string{"users/s/x", "users/s/v", "users/s/vault", "users/s/x/v"} {
		if err := checkSecretName(ok); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}
