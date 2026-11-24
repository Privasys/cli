// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// fakeIdentity is a self-consistent vault identity (its quote is not signed).
func fakeIdentity(t *testing.T, seed byte) PinnedIdentity {
	t.Helper()
	pub := make([]byte, 65)
	pub[0], pub[64] = 0x04, seed
	mid, err := vault.MemberID(pub)
	if err != nil {
		t.Fatal(err)
	}
	quote := make([]byte, 48+384)
	quote[0] = 3
	rd := vault.IdentityReportData(mid, "bill")
	copy(quote[48+320:], rd[:])
	return PinnedIdentity{vault.VaultIdentity{MemberID: mid, MemberPublicKey: hex.EncodeToString(pub), BillingID: "bill",
		MRENCLAVE: strings.Repeat("00", 32), QuoteB64: base64.RawURLEncoding.EncodeToString(quote)}}
}

// honestAnswer is what privasys.id returns for a: the binding asked for, with
// its approver, nonce and expiry.
func honestAnswer(t *testing.T, a ApprovalV2, now time.Time) map[string]interface{} {
	t.Helper()
	b := vault.BindingV2{Members: a.members(), Op: a.Operation, Handle: a.Handle, Target: a.Target,
		PolicyVersion: a.PolicyVersion, Approver: vault.OidcApprover(a.IssuerIndex, "sub-1"),
		Nonce: "AAECAwQFBgcICQoLDA0ODw", Exp: now.Unix() + 300}
	op, err := b.VaultOp()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{
		"publicKey": map[string]string{"challenge": op},
		"vault_op":  op,
		"binding": map[string]interface{}{
			"members": b.Members, "op": string(b.Op), "handle": b.Handle, "target": orDash(b.Target),
			"policy_version": b.PolicyVersion, "approver": b.Approver, "holder_head": "-",
			"nonce": b.Nonce, "exp": b.Exp,
		},
	}
}

func TestVerifyApprovalV2(t *testing.T) {
	now := time.Unix(1764000000, 0)
	policy := json.RawMessage(`{"version":1}`)
	pd, _ := vault.PolicyDigestJSON(policy)
	a := ApprovalV2{Operation: vault.BindUpdatePolicy, Handle: "apps.privasys.org/x/k", Target: pd,
		PolicyVersion: 4, Identities: []PinnedIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)},
		IssuerIndex: 1, NewPolicy: policy}
	if err := a.check(); err != nil {
		t.Fatal(err)
	}
	enc := func(m map[string]interface{}) []byte { b, _ := json.Marshal(m); return b }
	if _, _, err := verifyApprovalV2(a, enc(honestAnswer(t, a, now)), now); err != nil {
		t.Fatalf("an honest answer was refused: %v", err)
	}

	other := fakeIdentity(t, 9).MemberID()
	for name, mut := range map[string]func(m map[string]interface{}){
		"other vaults":    func(m map[string]interface{}) { bind(m)["members"] = []string{a.members()[0], other} },
		"fewer vaults":    func(m map[string]interface{}) { bind(m)["members"] = a.members()[:1] },
		"other op":        func(m map[string]interface{}) { bind(m)["op"] = "delete" },
		"other target":    func(m map[string]interface{}) { bind(m)["target"] = strings.Repeat("0", 64) },
		"other version":   func(m map[string]interface{}) { bind(m)["policy_version"] = 5 },
		"other issuer":    func(m map[string]interface{}) { bind(m)["approver"] = "oidc:0:sub-1" },
		"no sub":          func(m map[string]interface{}) { bind(m)["approver"] = "oidc:1:" },
		"holder head":     func(m map[string]interface{}) { bind(m)["holder_head"] = strings.Repeat("a", 64) },
		"short nonce":     func(m map[string]interface{}) { bind(m)["nonce"] = "AAEC" },
		"expired":         func(m map[string]interface{}) { bind(m)["exp"] = now.Unix() - 1 },
		"far exp":         func(m map[string]interface{}) { bind(m)["exp"] = now.Unix() + 3600 },
		"too little time": func(m map[string]interface{}) { bind(m)["exp"] = now.Unix() + 20 },
		"vault_op":        func(m map[string]interface{}) { m["vault_op"] = "x" },
		"challenge":       func(m map[string]interface{}) { m["publicKey"] = map[string]string{"challenge": "x"} },
	} {
		m := honestAnswer(t, a, now)
		mut(m)
		if _, _, err := verifyApprovalV2(a, enc(m), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func bind(m map[string]interface{}) map[string]interface{} {
	return m["binding"].(map[string]interface{})
}

func TestApprovalV2Check(t *testing.T) {
	ids := []PinnedIdentity{fakeIdentity(t, 1)}
	bad := fakeIdentity(t, 2)
	bad.id.BillingID = "other"
	for name, a := range map[string]ApprovalV2{
		"update without policy": {Operation: vault.BindUpdatePolicy, Target: "x", Identities: ids},
		"target not the policy": {Operation: vault.BindUpdatePolicy, Target: strings.Repeat("0", 64), NewPolicy: json.RawMessage(`{}`), Identities: ids},
		"policy on a delete":    {Operation: vault.BindDelete, NewPolicy: json.RawMessage(`{}`), Identities: ids},
		"no vaults":             {Operation: vault.BindDelete},
		"inconsistent identity": {Operation: vault.BindDelete, Identities: []PinnedIdentity{bad}},
	} {
		if err := a.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPinnedIdentityRelaysTheVaultsNames(t *testing.T) {
	raw, err := json.Marshal(fakeIdentity(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"member_id"`, `"member_public_key"`, `"billing_id"`, `"mrenclave"`, `"quote_b64"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("%s missing from %s", k, raw)
		}
	}
}
