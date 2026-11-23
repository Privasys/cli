// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"testing"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/config"
)

// A renew re-creates the secret on the ACTIVE constellation: every addressing
// field must come from it. (v0.56.1 shipped with the endpoints commented out,
// so every renew in place deleted the secret and then failed to re-create it.)
func TestRenewCreateParamsAddressTheActiveConstellation(t *testing.T) {
	s := &secretSession{env: &Env{Cfg: &config.Configuration{Issuer: "https://idp.test"}}, tok: "tok", sub: "sub", attTok: "att"}
	active := &api.VaultDirectory{
		ID: "c1", MRENCLAVE: "ab", AttestationServer: "https://as.test",
		Endpoints: []string{"10.0.0.1:1", "10.0.0.2:2"},
	}
	p := renewCreateParams(s, "users/sub/x", []byte("v"), 2, active)
	if len(p.Endpoints) != 2 || p.Endpoints[0] != "10.0.0.1:1" {
		t.Fatalf("endpoints = %v, want the active constellation's", p.Endpoints)
	}
	if p.MRENCLAVE != "ab" || p.AttServer != "https://as.test" || p.Threshold != 2 {
		t.Fatalf("addressing = %+v", p)
	}
	if !p.Exportable || p.Handle != "users/sub/x" || p.Bearer != "tok" || p.AttToken != "att" || p.Issuer != "https://idp.test" {
		t.Fatalf("params = %+v", p)
	}
}
