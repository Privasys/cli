// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/cli/internal/auth"
)

func TestAuthListNeverShowsTokens(t *testing.T) {
	c := &auth.Credential{
		Issuer: "https://privasys.id", Subject: "sub", AccessToken: "ACCESS-SECRET-VALUE",
		IDToken: "ID-SECRET-VALUE", RefreshToken: "REFRESH-SECRET-VALUE", ServiceKey: "SERVICE-SECRET-VALUE",
		AccessExpiresAt: time.Unix(1800000000, 0).UTC(),
		AudienceTokens:  map[string]auth.AudienceToken{"privasys-platform-test": {AccessToken: "AUD-SECRET-VALUE", ExpiresAt: time.Unix(1800000000, 0).UTC()}},
	}
	b, err := json.Marshal(summarizeCredential(c))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, "SECRET-VALUE") {
		t.Fatalf("a token value was listed: %s", out)
	}
	for _, want := range []string{`"has_refresh_token":true`, `"has_id_token":true`, `"access_token_fingerprint":"sha256:`, `"audience":"privasys-platform-test"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}
