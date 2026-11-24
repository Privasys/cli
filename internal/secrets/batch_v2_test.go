// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// honestBatch is privasys.id's answer to a v2 batch: each entry's binding as a
// single begin gives it, all with the batch's expiry, and the v1 batch id over
// their v2 vault_ops in the order asked.
func honestBatch(t *testing.T, label string, entries []ApprovalV2, now time.Time) map[string]interface{} {
	t.Helper()
	exp := now.Unix() + 300
	var list []map[string]interface{}
	var forID []BatchEntry
	for _, a := range entries {
		single := honestAnswer(t, a, now)
		b := single["binding"].(map[string]interface{})
		b["exp"] = exp
		bv := vault.BindingV2{Members: a.members(), Op: a.Operation, Handle: a.Handle, Target: a.Target,
			PolicyVersion: a.PolicyVersion, Approver: b["approver"].(string), Nonce: b["nonce"].(string), Exp: exp}
		op, err := bv.VaultOp()
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, map[string]interface{}{"operation": string(a.Operation), "handle": a.Handle, "vault_op": op, "binding": b})
		forID = append(forID, BatchEntry{Operation: string(a.Operation), VaultOp: op})
	}
	id := computeBatchID(label, exp, forID)
	return map[string]interface{}{"batch_id": id, "publicKey": map[string]string{"challenge": id}, "exp": exp, "entries": list}
}

func TestVerifyBatchV2(t *testing.T) {
	now := time.Unix(1764000000, 0)
	ids := []vault.VaultIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)}
	other := []vault.VaultIdentity{fakeIdentity(t, 3)}
	entries := []ApprovalV2{
		{Operation: vault.BindPromote, Handle: "apps.privasys.org/a/k", Target: strings.Repeat("1", 64), PolicyVersion: 2, Identities: ids},
		{Operation: vault.BindPromote, Handle: "apps.privasys.org/b/k", Target: strings.Repeat("2", 64), PolicyVersion: 7, Identities: other, IssuerIndex: 1},
	}
	enc := func(m map[string]interface{}) []byte { b, _ := json.Marshal(m); return b }
	b, err := verifyBatchV2("roll", entries, enc(honestBatch(t, "roll", entries, now)), now)
	if err != nil {
		t.Fatalf("an honest batch was refused: %v", err)
	}
	if len(b.Entries) != 2 || b.Entries[1].PolicyVersion != 7 || b.Entries[0].VaultOp == "" {
		t.Fatalf("batch entries: %+v", b.Entries)
	}

	ent := func(m map[string]interface{}, i int) map[string]interface{} {
		return m["entries"].([]map[string]interface{})[i]
	}
	for name, mut := range map[string]func(m map[string]interface{}){
		"reordered": func(m map[string]interface{}) {
			l := m["entries"].([]map[string]interface{})
			l[0], l[1] = l[1], l[0]
		},
		"dropped":      func(m map[string]interface{}) { m["entries"] = m["entries"].([]map[string]interface{})[:1] },
		"other vaults": func(m map[string]interface{}) { ent(m, 1)["binding"].(map[string]interface{})["members"] = ids[0:1] },
		"entry exp": func(m map[string]interface{}) {
			ent(m, 0)["binding"].(map[string]interface{})["exp"] = now.Unix() + 200
		},
		"entry vaultop": func(m map[string]interface{}) { ent(m, 0)["vault_op"] = "x" },
		"batch id":      func(m map[string]interface{}) { m["batch_id"] = "x" },
		"challenge":     func(m map[string]interface{}) { m["publicKey"] = map[string]string{"challenge": "x"} },
	} {
		m := honestBatch(t, "roll", entries, now)
		mut(m)
		if _, err := verifyBatchV2("roll", entries, enc(m), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := verifyBatchV2("other label", entries, enc(honestBatch(t, "roll", entries, now)), now); err == nil {
		t.Error("a batch id over another label was accepted")
	}
}

func TestBatchV2NeverBatchesExportOrDelete(t *testing.T) {
	ids := []vault.VaultIdentity{fakeIdentity(t, 1)}
	for _, op := range []vault.BindingOp{vault.BindExport, vault.BindDelete, vault.BindExportAssembled, vault.BindIssuerDelete} {
		_, err := BeginBatchV2(t.Context(), "http://127.0.0.1:1", "b", "l", "", []ApprovalV2{{Operation: op, Handle: "h", Identities: ids}})
		if err == nil || !strings.Contains(err.Error(), "never approved in a batch") {
			t.Errorf("%s: %v", op, err)
		}
	}
}
