// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"testing"

	"github.com/Privasys/cli/internal/secrets"
)

func TestEd25519KeyTypeAndJWK(t *testing.T) {
	for _, in := range []string{"ed25519", "Ed25519", "eddsa", "FrostEd25519"} {
		kt, operational, err := resolveVaultKeyType(in)
		if err != nil || kt != secrets.ThresholdKeyType || !operational {
			t.Fatalf("resolveVaultKeyType(%q) = %q, %t, %v", in, kt, operational, err)
		}
	}
	pub := make([]byte, 32)
	pub[0] = 0xd7
	jwk, err := jwkFromPublicKey(secrets.ThresholdKeyType, pub)
	if err != nil {
		t.Fatal(err)
	}
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || jwk["x"] != "1wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("jwk = %v", jwk)
	}
	if _, ok := jwk["y"]; ok {
		t.Fatal("an OKP JWK has no y")
	}
	if _, err := jwkFromPublicKey(secrets.ThresholdKeyType, pub[:31]); err == nil {
		t.Fatal("a 31-byte key must be refused")
	}
}
