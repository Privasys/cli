// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

// One approval for a list of v2 operations on issuer-owned keys.
//
// The identities of every vault any entry names go once, at the top, so a
// batch can span constellations without repeating quotes. privasys.id answers
// each entry with its binding and vault_op, as for a single approval; the CLI
// verifies each one and the batch id over them, then collects one token per
// entry exactly as for a v1 batch.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// batchableV2 says whether an operation may be approved in a batch. Export and
// delete never are; delete_after only beside its successor (checkDeleteAfter).
func batchableV2(op vault.BindingOp) bool {
	switch op {
	case vault.BindCreate, vault.BindPromote, vault.BindUpdatePolicy, vault.BindReshare, vault.BindIssuerUpdate,
		vault.BindDeleteAfter:
		return true
	}
	return false
}

// checkDeleteAfter requires every delete_after to name a successor promoted or
// created in the same batch, so the old key's delete is approved only with the
// migration or upgrade it follows.
func checkDeleteAfter(entries []ApprovalV2) error {
	successors := map[string]string{} // delete_after target -> successor handle
	for _, a := range entries {
		var target string
		switch a.Operation {
		case vault.BindPromote:
			target = a.Target
		case vault.BindCreate:
			target = ""
		default:
			continue
		}
		t, err := vault.DeleteAfterTarget(a.Handle, target)
		if err != nil {
			return err
		}
		successors[t] = a.Handle
	}
	for _, a := range entries {
		if a.Operation != vault.BindDeleteAfter {
			continue
		}
		succ, ok := successors[a.Target]
		if !ok {
			return fmt.Errorf("the delete of %s names no successor promoted or created in this batch", a.Handle)
		}
		// A key is never its own successor: the vault would find "the
		// successor" promoted and delete the key just promoted.
		if succ == a.Handle {
			return fmt.Errorf("the delete of %s names itself as its successor", a.Handle)
		}
	}
	return nil
}

type batchV2Answer struct {
	BatchID   string `json:"batch_id"`
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
	Exp     int64 `json:"exp"`
	Entries []struct {
		Operation string        `json:"operation"`
		Handle    string        `json:"handle"`
		VaultOp   string        `json:"vault_op"`
		Binding   bindingAnswer `json:"binding"`
	} `json:"entries"`
	PushRegistered   *bool  `json:"push_registered"`
	ApprovalDeeplink string `json:"approval_deeplink"`
}

// BeginBatchV2 opens a v2 batch at privasys.id and verifies its answer. Every
// entry's token is issued for audience ("" = privasys.id's default). The
// result is shown and collected with ShowBatch and CollectBatchTokens.
func BeginBatchV2(ctx context.Context, issuer, bearer, label, audience string, entries []ApprovalV2) (*Batch, error) {
	if len(entries) == 0 || len(entries) > MaxBatchEntries {
		return nil, fmt.Errorf("a batch holds 1 to %d operations", MaxBatchEntries)
	}
	for _, a := range entries {
		if a.SuccessorHandle != "" {
			// This CLI asks for a created successor's delete_after alone.
			return nil, fmt.Errorf("the delete_after of %s names its successor and is approved on its own, not in a batch", a.Handle)
		}
	}
	if err := checkDeleteAfter(entries); err != nil {
		return nil, err
	}
	identities := []PinnedIdentity{}
	seen := map[string]bool{}
	reqEntries := make([]map[string]interface{}, 0, len(entries))
	keys := map[string]bool{}
	for _, a := range entries {
		if !batchableV2(a.Operation) {
			return nil, fmt.Errorf("a %s is never approved in a batch", a.Operation)
		}
		if err := a.check(); err != nil {
			return nil, err
		}
		k := string(a.Operation) + " " + a.Handle
		if keys[k] {
			return nil, fmt.Errorf("%s is in the batch twice", k)
		}
		keys[k] = true
		for _, id := range a.Identities {
			if !seen[id.MemberID()] {
				seen[id.MemberID()] = true
				identities = append(identities, id)
			}
		}
		e := map[string]interface{}{
			"operation":      a.Operation,
			"handle":         a.Handle,
			"target":         orDash(a.Target),
			"policy_version": a.PolicyVersion,
			"members":        a.members(),
			"issuer_index":   a.IssuerIndex,
			"context":        a.Context,
		}
		if len(a.NewPolicy) != 0 {
			e["new_policy"] = a.NewPolicy
		}
		if a.TTLSeconds != 0 {
			e["ttl_seconds"] = a.TTLSeconds
		}
		reqEntries = append(reqEntries, e)
	}
	begin := map[string]interface{}{
		"binding_version":   2,
		"label":             label,
		"ttl_seconds":       batchTTLSeconds,
		"member_identities": identities,
		"entries":           reqEntries,
	}
	if audience != "" {
		begin["audience"] = audience
	}
	body, err := json.Marshal(begin)
	if err != nil {
		return nil, err
	}
	issuer = strings.TrimRight(issuer, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/fido2/vault-approval/batch/begin", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("batch begin: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &refusal) == nil && refusal.Error != "" {
			return nil, fmt.Errorf("the identity provider refused the batch: %s", refusal.Error)
		}
		return nil, fmt.Errorf("batch begin -> %d: %s", resp.StatusCode, data)
	}
	b, err := verifyBatchV2(label, entries, data, time.Now())
	if err != nil {
		return nil, fmt.Errorf("refusing the batch: %w", err)
	}
	return b, nil
}

// verifyBatchV2 checks every entry's binding against what was asked, that all
// share the batch's expiry, and that the batch id and challenge cover exactly
// those entries.
func verifyBatchV2(label string, requested []ApprovalV2, answer []byte, now time.Time) (*Batch, error) {
	var ans batchV2Answer
	if err := json.Unmarshal(answer, &ans); err != nil {
		return nil, errors.New("unreadable answer")
	}
	if len(ans.Entries) != len(requested) {
		return nil, fmt.Errorf("the server returned %d operations, %d were requested", len(ans.Entries), len(requested))
	}
	out := &Batch{ID: ans.BatchID, Label: label, Exp: ans.Exp,
		PushRegistered: ans.PushRegistered, Deeplink: ans.ApprovalDeeplink}
	// privasys.id returns the entries in its canonical order (by handle, then
	// operation), and the batch id covers that order. Each entry is matched to
	// what was asked by operation and handle: every asked entry exactly once,
	// nothing else.
	asked := make(map[string]ApprovalV2, len(requested))
	for _, a := range requested {
		k := string(a.Operation) + " " + a.Handle
		if _, dup := asked[k]; dup {
			return nil, fmt.Errorf("%s was asked twice", k)
		}
		asked[k] = a
	}
	for i, e := range ans.Entries {
		k := e.Operation + " " + e.Handle
		a, ok := asked[k]
		if !ok {
			return nil, fmt.Errorf("entry %d is %s, which was not asked or is listed twice", i, k)
		}
		delete(asked, k)
		// Every entry expires with the batch, except a delete_after, which is
		// held until the migration ends and may last up to 24 hours.
		if a.Operation == vault.BindDeleteAfter {
			if e.Binding.Exp < ans.Exp {
				return nil, fmt.Errorf("%s expires before the batch", k)
			}
		} else if e.Binding.Exp != ans.Exp {
			return nil, fmt.Errorf("%s expires at another time than the batch", k)
		}
		b, vaultOp, err := verifyBindingV2(a, e.Binding, e.VaultOp, now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out.Entries = append(out.Entries, BatchEntry{Operation: e.Operation, Handle: e.Handle,
			MeasurementDigest: orDash(a.Target), PolicyVersion: a.PolicyVersion, Nonce: b.Nonce, VaultOp: vaultOp,
			Exp: b.Exp})
	}
	if ans.BatchID != computeBatchID(label, ans.Exp, out.Entries) {
		return nil, errors.New("the batch id does not match the list")
	}
	if strings.TrimRight(ans.PublicKey.Challenge, "=") != ans.BatchID {
		return nil, errors.New("the approval's challenge is not the batch id")
	}
	return out, nil
}
