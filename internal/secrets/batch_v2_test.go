// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/base64"
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
		entryExp := exp
		if a.Operation == vault.BindDeleteAfter {
			entryExp = now.Unix() + 86000
		}
		b["exp"] = entryExp
		bv := vault.BindingV2{Members: a.members(), Op: a.Operation, Handle: a.Handle, Target: a.Target,
			PolicyVersion: a.PolicyVersion, Approver: b["approver"].(string), Nonce: b["nonce"].(string), Exp: entryExp}
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
	ids := []PinnedIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)}
	other := []PinnedIdentity{fakeIdentity(t, 3)}
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
	ids := []PinnedIdentity{fakeIdentity(t, 1)}
	for _, op := range []vault.BindingOp{vault.BindExport, vault.BindDelete, vault.BindExportAssembled, vault.BindIssuerDelete} {
		_, err := BeginBatchV2(t.Context(), "http://127.0.0.1:1", "b", "l", "", []ApprovalV2{{Operation: op, Handle: "h", Identities: ids}})
		if err == nil || !strings.Contains(err.Error(), "never approved in a batch") {
			t.Errorf("%s: %v", op, err)
		}
	}
}

func TestBatchV2DeleteAfter(t *testing.T) {
	now := time.Unix(1764000000, 0)
	ids := []PinnedIdentity{fakeIdentity(t, 1)}
	profile := strings.Repeat("e", 64)
	succ, _ := vault.DeleteAfterTarget("apps.privasys.org/new/k", profile)
	entries := []ApprovalV2{
		{Operation: vault.BindPromote, Handle: "apps.privasys.org/new/k", Target: profile, PolicyVersion: 1, Identities: ids},
		{Operation: vault.BindDeleteAfter, Handle: "apps.privasys.org/old/k", Target: succ, PolicyVersion: 4, Identities: ids, TTLSeconds: 86400},
	}
	if err := checkDeleteAfter(entries); err != nil {
		t.Fatal(err)
	}
	enc := func(m map[string]interface{}) []byte { b, _ := json.Marshal(m); return b }
	b, err := verifyBatchV2("migrate", entries, enc(honestBatch(t, "migrate", entries, now)), now)
	if err != nil {
		t.Fatalf("an honest migrate batch was refused: %v", err)
	}
	if b.Entries[1].Exp != now.Unix()+86000 || b.Entries[0].Exp != b.Exp {
		t.Fatalf("entry expiries: %+v", b.Entries)
	}

	// The token check uses the entry's own expiry.
	jwt := func(op, nonce string, exp int64) string {
		c, _ := json.Marshal(map[string]interface{}{"vault_op": op, "nonce": nonce, "exp": exp})
		return "e30." + base64.RawURLEncoding.EncodeToString(c) + ".sig"
	}
	var toks []batchToken
	for _, e := range b.Entries {
		exp := b.Exp
		if e.Exp != 0 {
			exp = e.Exp
		}
		toks = append(toks, batchToken{Operation: e.Operation, Handle: e.Handle, VaultOp: e.VaultOp, AccessToken: jwt(e.VaultOp, e.Nonce, exp)})
	}
	if _, err := verifyBatchTokens(b, toks); err != nil {
		t.Fatalf("the delete_after token was refused: %v", err)
	}

	// No successor in the batch.
	if err := checkDeleteAfter(entries[1:]); err == nil {
		t.Error("a delete_after without its successor was accepted")
	}
	// A successor with another profile.
	other := append([]ApprovalV2(nil), entries...)
	other[0].Target = strings.Repeat("f", 64)
	if err := checkDeleteAfter(other); err == nil {
		t.Error("a delete_after for another promote was accepted")
	}
	for name, exp := range map[string]int64{"shorter than the batch": now.Unix() + 100, "beyond 24 h": now.Unix() + 86400 + 600} {
		m := honestBatch(t, "migrate", entries, now)
		m["entries"].([]map[string]interface{})[1]["binding"].(map[string]interface{})["exp"] = exp
		if _, err := verifyBatchV2("migrate", entries, enc(m), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Only delete_after may outlive the batch.
	m := honestBatch(t, "migrate", entries, now)
	m["entries"].([]map[string]interface{})[0]["binding"].(map[string]interface{})["exp"] = now.Unix() + 3600
	if _, err := verifyBatchV2("migrate", entries, enc(m), now); err == nil {
		t.Error("a promote outliving the batch was accepted")
	}
}

func TestDeleteAfterGuards(t *testing.T) {
	now := time.Unix(1764000000, 0)
	ids := []PinnedIdentity{fakeIdentity(t, 1)}
	profile := strings.Repeat("e", 64)

	// A key named as its own successor.
	self, _ := vault.DeleteAfterTarget("apps.privasys.org/k", profile)
	if err := checkDeleteAfter([]ApprovalV2{
		{Operation: vault.BindPromote, Handle: "apps.privasys.org/k", Target: profile, Identities: ids},
		{Operation: vault.BindDeleteAfter, Handle: "apps.privasys.org/k", Target: self, Identities: ids},
	}); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Errorf("a key deleting itself after its own promote: %v", err)
	}

	// Never on its own.
	if _, err := RequestApprovalV2(t.Context(), "http://127.0.0.1:1", "b",
		ApprovalV2{Operation: vault.BindDeleteAfter, Handle: "h", Target: self, Identities: ids}, nil, nil); err == nil || !strings.Contains(err.Error(), "only in a batch") {
		t.Errorf("a single delete_after: %v", err)
	}

	// The lifetime is the delete_after's alone, within bounds.
	for name, a := range map[string]ApprovalV2{
		"ttl on a promote": {Operation: vault.BindPromote, Handle: "h", Target: profile, Identities: ids, TTLSeconds: 600},
		"ttl beyond 24 h":  {Operation: vault.BindDeleteAfter, Handle: "h", Target: self, Identities: ids, TTLSeconds: 86401},
		"ttl too short":    {Operation: vault.BindDeleteAfter, Handle: "h", Target: self, Identities: ids, TTLSeconds: 5},
	} {
		if err := a.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The answer may not outlive what was asked (default: an hour).
	succ, _ := vault.DeleteAfterTarget("apps.privasys.org/new/k", profile)
	entries := []ApprovalV2{
		{Operation: vault.BindPromote, Handle: "apps.privasys.org/new/k", Target: profile, PolicyVersion: 1, Identities: ids},
		{Operation: vault.BindDeleteAfter, Handle: "apps.privasys.org/old/k", Target: succ, PolicyVersion: 4, Identities: ids},
	}
	enc := func(m map[string]interface{}) []byte { b, _ := json.Marshal(m); return b }
	if _, err := verifyBatchV2("migrate", entries, enc(honestBatch(t, "migrate", entries, now)), now); err == nil {
		t.Error("a 24 h delete_after was accepted where an hour was asked")
	}
}

// privasys.id answers in its canonical order (by handle, then operation), and
// the batch id covers that order, not the order asked.
func TestVerifyBatchV2ServerOrder(t *testing.T) {
	now := time.Unix(1764000000, 0)
	ids := []PinnedIdentity{fakeIdentity(t, 1), fakeIdentity(t, 2)}
	a := ApprovalV2{Operation: vault.BindPromote, Handle: "apps.privasys.org/a/k", Target: strings.Repeat("1", 64), PolicyVersion: 2, Identities: ids}
	b := ApprovalV2{Operation: vault.BindPromote, Handle: "apps.privasys.org/b/k", Target: strings.Repeat("2", 64), PolicyVersion: 7, Identities: ids}
	enc := func(m map[string]interface{}) []byte { x, _ := json.Marshal(m); return x }

	got, err := verifyBatchV2("roll", []ApprovalV2{b, a}, enc(honestBatch(t, "roll", []ApprovalV2{a, b}, now)), now)
	if err != nil {
		t.Fatalf("a batch in the server's order was refused: %v", err)
	}
	if got.Entries[0].PolicyVersion != 2 || got.Entries[1].PolicyVersion != 7 {
		t.Fatalf("entries are not in the server's order: %+v", got.Entries)
	}

	// The same entry twice, the other missing: refused.
	m := honestBatch(t, "roll", []ApprovalV2{a, b}, now)
	list := m["entries"].([]map[string]interface{})
	list[1] = list[0]
	if _, err := verifyBatchV2("roll", []ApprovalV2{a, b}, enc(m), now); err == nil {
		t.Fatal("a batch listing one entry twice was accepted")
	}

	// The same entry asked twice: refused before anything else.
	if _, err := verifyBatchV2("roll", []ApprovalV2{a, a}, enc(honestBatch(t, "roll", []ApprovalV2{a, a}, now)), now); err == nil {
		t.Fatal("a request asking one entry twice was accepted")
	}
}
