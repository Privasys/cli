// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/config"
)

// TestLiveRetireCheckStoredDefaults runs the retire check on a real stored
// policy: PRIVASYS_LIVE_RETIRE_HANDLE and _CONSTELLATION (its id on the dev
// control plane). It reads and canonicalises only; it changes
// nothing on the vaults.
func TestLiveRetireCheckStoredDefaults(t *testing.T) {
	handle := os.Getenv("PRIVASYS_LIVE_RETIRE_HANDLE")
	if handle == "" {
		t.Skip("PRIVASYS_LIVE_RETIRE_HANDLE not set")
	}
	ctx := context.Background()
	// The constellation as the dev control plane lists it.
	cpTok, err := auth.AccessTokenForAudience(ctx, "https://privasys.id", config.TestAudience)
	if err != nil {
		t.Fatal(err)
	}
	d, err := api.New(config.TestEndpoint, cpTok).VaultDirectoryAt(ctx, os.Getenv("PRIVASYS_LIVE_RETIRE_CONSTELLATION"))
	if err != nil {
		t.Fatal(err)
	}
	ownerTok, err := auth.VaultTokenFor(ctx, "https://privasys.id", d.OIDCAudience)
	if err != nil {
		t.Fatal(err)
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, "https://privasys.id", "attestation-server")
	stored, _, err := CurrentPolicy(ctx, d, ownerTok, attTok, handle)
	if err != nil {
		t.Fatal(err)
	}
	// The control plane's form: the typed policy marshalled again.
	var kp vault.KeyPolicy
	if err := json.Unmarshal(stored, &kp); err != nil {
		t.Fatal(err)
	}
	typed, _ := json.Marshal(kp)
	rawPD, _ := vault.PolicyDigestJSON(stored)
	typedPD, _ := vault.PolicyDigestJSON(typed)
	t.Logf("PD(stored) %s, PD(typed) %s, differ: %t", rawPD, typedPD, rawPD != typedPD)

	canon := VaultCanonicaliser(d, ownerTok, attTok)
	a, err := canonicalPD(ctx, canon, stored)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalPD(ctx, canon, typed)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("the vaults canonicalise the stored and the typed form differently: %s vs %s", a, b)
	}

	// A retire on that stored form: add a synthetic older tee in front,
	// retire it, and the typed current policy must be accepted.
	doc, _ := decodeTree(stored)
	root := doc.(map[string]any)
	tees := root["principals"].(map[string]any)["tees"].([]any)
	fake, _ := decodeTree(json.RawMessage(teeJSON(strings.Repeat("e", 64))))
	root["principals"].(map[string]any)["tees"] = append([]any{fake}, tees...)
	withOld, _ := json.Marshal(root)
	if err := CheckRetireChange(ctx, withOld, typed, strings.Repeat("e", 64), canon); err != nil {
		t.Fatalf("an honest retire on the real stored policy was refused: %v", err)
	}
}
