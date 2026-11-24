// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type batchVectors struct {
	BatchID      string       `json:"batch_id"`
	Domain       string       `json:"domain"`
	SingleDomain string       `json:"single_domain"`
	Entries      []BatchEntry `json:"entries"`
	Exp          int64        `json:"exp"`
	Label        string       `json:"label"`
}

// The identity provider generates these vectors; the wallet checks the same ones.
func loadBatchVectors(t *testing.T) batchVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vault-approval-batch-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v batchVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBatchBindingMatchesTheSharedVectors(t *testing.T) {
	v := loadBatchVectors(t)
	if v.Domain != vaultBatchDomain || v.SingleDomain != vaultApprovalDomain {
		t.Fatalf("domains: %q, %q", v.Domain, v.SingleDomain)
	}
	for _, e := range v.Entries {
		if got := computeVaultOp(e.Handle, e.MeasurementDigest, e.PolicyVersion, e.Nonce, v.Exp); got != e.VaultOp {
			t.Errorf("%s: vault_op %s, want %s", e.Key(), got, e.VaultOp)
		}
	}
	if got := computeBatchID(v.Label, v.Exp, v.Entries); got != v.BatchID {
		t.Errorf("batch_id %s, want %s", got, v.BatchID)
	}
}

func TestVerifyBatchRefusesATamperedAnswer(t *testing.T) {
	v := loadBatchVectors(t)
	now := time.Unix(v.Exp-250, 0)
	requested := func() []BatchEntry {
		out := make([]BatchEntry, len(v.Entries))
		for i, e := range v.Entries {
			e.Nonce, e.VaultOp = "", ""
			out[i] = e
		}
		return out
	}
	clone := func() []BatchEntry { return append([]BatchEntry(nil), v.Entries...) }
	rebind := func(entries []BatchEntry) string { return computeBatchID(v.Label, v.Exp, entries) }

	if err := verifyBatch(v.Label, requested(), v.BatchID, v.BatchID, v.Exp, v.Entries, now); err != nil {
		t.Fatalf("the honest answer was refused: %v", err)
	}
	cases := map[string]func() error{
		"an entry dropped": func() error {
			e := clone()[:2]
			return verifyBatch(v.Label, requested(), rebind(e), rebind(e), v.Exp, e, now)
		},
		"an operation not requested": func() error {
			e := clone()
			e[2].Handle = "apps.privasys.org/cccc/storage-kek/v1"
			e[2].VaultOp = computeVaultOp(e[2].Handle, e[2].MeasurementDigest, e[2].PolicyVersion, e[2].Nonce, v.Exp)
			return verifyBatch(v.Label, requested(), rebind(e), rebind(e), v.Exp, e, now)
		},
		"another measurement": func() error {
			e := clone()
			e[1].MeasurementDigest = strings.Repeat("3", 64)
			e[1].VaultOp = computeVaultOp(e[1].Handle, e[1].MeasurementDigest, e[1].PolicyVersion, e[1].Nonce, v.Exp)
			return verifyBatch(v.Label, requested(), rebind(e), rebind(e), v.Exp, e, now)
		},
		"another policy version": func() error {
			e := clone()
			e[1].PolicyVersion++
			e[1].VaultOp = computeVaultOp(e[1].Handle, e[1].MeasurementDigest, e[1].PolicyVersion, e[1].Nonce, v.Exp)
			return verifyBatch(v.Label, requested(), rebind(e), rebind(e), v.Exp, e, now)
		},
		"a vault_op that binds something else": func() error {
			e := clone()
			e[0].VaultOp = e[1].VaultOp
			return verifyBatch(v.Label, requested(), rebind(e), rebind(e), v.Exp, e, now)
		},
		"a reordered list": func() error {
			e := clone()
			e[0], e[2] = e[2], e[0]
			return verifyBatch(v.Label, requested(), rebind(e), rebind(e), v.Exp, e, now)
		},
		"a changed label": func() error {
			return verifyBatch("Something else", requested(), v.BatchID, v.BatchID, v.Exp, v.Entries, now)
		},
		"a batch id for another list": func() error {
			return verifyBatch(v.Label, requested(), rebind(clone()[:1]), v.BatchID, v.Exp, v.Entries, now)
		},
		"a challenge that is not the batch id": func() error {
			other := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			return verifyBatch(v.Label, requested(), v.BatchID, other, v.Exp, v.Entries, now)
		},
		"already expired": func() error {
			return verifyBatch(v.Label, requested(), v.BatchID, v.BatchID, v.Exp, v.Entries, time.Unix(v.Exp+1, 0))
		},
		"a lifetime beyond the limit": func() error {
			return verifyBatch(v.Label, requested(), v.BatchID, v.BatchID, v.Exp, v.Entries, time.Unix(v.Exp-3600, 0))
		},
	}
	for name, check := range cases {
		if check() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func fakeJWT(t *testing.T, vaultOp, nonce string, exp int64) string {
	t.Helper()
	claims, _ := json.Marshal(batchTokenClaims{VaultOp: vaultOp, Nonce: nonce, Exp: exp})
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
}

func TestVerifyBatchTokens(t *testing.T) {
	v := loadBatchVectors(t)
	b := &Batch{ID: v.BatchID, Exp: v.Exp, Entries: v.Entries}
	honest := func() []batchToken {
		out := make([]batchToken, 0, len(v.Entries))
		for _, e := range v.Entries {
			out = append(out, batchToken{e.Operation, e.Handle, e.VaultOp, fakeJWT(t, e.VaultOp, e.Nonce, v.Exp)})
		}
		return out
	}
	got, err := verifyBatchTokens(b, honest())
	if err != nil || len(got) != len(v.Entries) {
		t.Fatalf("honest tokens: %d, %v", len(got), err)
	}
	swapped := honest()
	swapped[0].AccessToken, swapped[1].AccessToken = swapped[1].AccessToken, swapped[0].AccessToken
	if _, err := verifyBatchTokens(b, swapped); err == nil {
		t.Error("tokens swapped between entries were accepted")
	}
	if _, err := verifyBatchTokens(b, honest()[:2]); err == nil {
		t.Error("a missing token was accepted")
	}
	late := honest()
	late[0].AccessToken = fakeJWT(t, v.Entries[0].VaultOp, v.Entries[0].Nonce, v.Exp+60)
	if _, err := verifyBatchTokens(b, late); err == nil {
		t.Error("a token with another expiry was accepted")
	}
}

// A lost push must not strand the owner: the link is shown whatever the server
// sent, and a link that is not a batch approval is never rendered.
func TestShowBatchAlwaysShowsTheLink(t *testing.T) {
	const id = "fMYR8ksLNFmyC92yHO12RYqjR-ujjoRUYaX0bWLwOQk"
	own := "privasys-wallet://vault-approvals?batch_id=" + id
	dev := "privasys-wallet-dev://vault-approvals?batch_id=" + id
	cases := map[string]string{"": own, own: own, dev: dev, "https://evil.example/?batch_id=" + id: own}
	for link, want := range cases {
		var out bytes.Buffer
		ShowBatch(&out, &Batch{ID: id, Label: "l", Deeplink: link})
		if !strings.Contains(out.String(), "Link: "+want+"\n") {
			t.Errorf("deeplink %q: the output does not show %s", link, want)
		}
		if strings.Contains(out.String(), "evil.example") {
			t.Errorf("deeplink %q was rendered", link)
		}
	}
}

func TestBeginBatchSurfacesTheServersRefusal(t *testing.T) {
	const reason = "label must not contain control, format or bidirectional characters"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
	}))
	defer srv.Close()
	_, err := BeginBatch(context.Background(), srv.URL, "tok", "label", "", nil)
	if err == nil || !strings.HasSuffix(err.Error(), reason) {
		t.Errorf("err = %v", err)
	}
}

func TestCollectBatchTokensStopsWhenDeclined(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"status":"declined"}`))
	}))
	defer srv.Close()
	b := &Batch{ID: "id", Exp: time.Now().Unix() + 300}
	if _, err := CollectBatchTokens(context.Background(), srv.URL, "tok", b); !errors.Is(err, ErrDeclined) || polls != 1 {
		t.Errorf("err = %v after %d polls", err, polls)
	}
}

func TestBeginBatchSaysWhenTheServerHasNoBatches(t *testing.T) {
	cases := []struct {
		status      int
		body        string
		unavailable bool
	}{
		{http.StatusNotFound, `404 page not found`, true},
		{http.StatusMethodNotAllowed, ``, true},
		{http.StatusNotFound, `{"error":"no credentials for user"}`, false},
		{http.StatusBadRequest, `{"error":"operation cannot be batched"}`, false},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		_, err := BeginBatch(context.Background(), srv.URL, "tok", "label", "", nil)
		srv.Close()
		if err == nil || errors.Is(err, ErrBatchUnavailable) != c.unavailable {
			t.Errorf("%d %q: %v", c.status, c.body, err)
		}
	}
}
