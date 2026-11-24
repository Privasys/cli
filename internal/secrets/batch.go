// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

// One approval for a list of vault operations.
//
// Rolling a host promotes every key on it. A batch lets the owner approve the
// whole list with one assertion, after which the identity provider issues one
// ordinary operation-bound token per entry, so each vault sees exactly the
// token it accepts for a single approval.
//
//	POST /fido2/vault-approval/batch/begin   (the list)
//	GET  /fido2/vault-approval/batch/token   (one token per entry, once)
//
// The CLI does not take the server's answer on trust: it recomputes every
// vault_op and the batch id from the operations it asked for, and refuses a
// list that differs. testdata/vault-approval-batch-vectors.json pins the bytes
// against the identity provider and the wallet.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	vaultApprovalDomain = "privasys-vault-approval/v1"
	vaultBatchDomain    = "privasys-vault-approval-batch-v1"

	// MaxBatchEntries is the most operations one approval may cover.
	MaxBatchEntries = 32
	// batchTTLSeconds is the identity provider's cap, and the vaults' freshness rule.
	batchTTLSeconds = 300
	// batchClockSkew tolerates a difference between this machine's clock and the server's.
	batchClockSkew = 120
)

// ErrBatchUnavailable says the identity provider has no batch endpoints yet.
var ErrBatchUnavailable = errors.New("the identity provider does not offer batch approvals yet")

// ErrDeclined says the owner declined the approval in the wallet: the token
// poll answers 410 {"status":"declined"}, once. Nothing may be carried out, and
// nothing should be asked again on its own.
var ErrDeclined = errors.New("declined on the phone")

// isDeclined reads a token poll's answer after the owner declined.
func isDeclined(status int, body []byte) bool {
	if status != http.StatusGone {
		return false
	}
	var s struct {
		Status string `json:"status"`
	}
	return json.Unmarshal(body, &s) == nil && s.Status == "declined"
}

// batchDeeplink is the only link the CLI renders as a QR for a batch.
var batchDeeplink = regexp.MustCompile(`^privasys-wallet(-dev|-preview)?://vault-approvals\?batch_id=[A-Za-z0-9_-]+$`)

// BatchEntry is one operation of a batch.
type BatchEntry struct {
	Operation         string            `json:"operation"`
	Handle            string            `json:"handle"`
	MeasurementDigest string            `json:"measurement_digest"`
	PolicyVersion     uint64            `json:"policy_version"`
	Nonce             string            `json:"nonce,omitempty"`
	VaultOp           string            `json:"vault_op,omitempty"`
	Context           map[string]string `json:"context,omitempty"`
}

// Key names an entry within a batch.
func (e BatchEntry) Key() string { return e.Operation + " " + e.Handle }

// Batch is a list the identity provider accepted and the CLI verified.
type Batch struct {
	ID             string
	Label          string
	Exp            int64
	Entries        []BatchEntry
	PushRegistered *bool
	Deeplink       string
}

// computeVaultOp is the binding each vault recomputes for one operation.
func computeVaultOp(handle, measurementDigest string, policyVersion uint64, nonce string, exp int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%d",
		vaultApprovalDomain, handle, measurementDigest, policyVersion, nonce, exp)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// computeBatchID is the binding the owner's assertion signs.
func computeBatchID(label string, exp int64, entries []BatchEntry) string {
	var b strings.Builder
	b.WriteString(vaultBatchDomain + "\n" + label + "\n" + strconv.FormatInt(exp, 10) + "\n" + strconv.Itoa(len(entries)))
	for _, e := range entries {
		b.WriteString("\n" + e.Operation + " " + e.VaultOp)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyBatch checks the server's answer against the operations requested: the
// same operations, in canonical order, each vault_op and the batch id
// recomputed, and the challenge being that batch id.
func verifyBatch(label string, requested []BatchEntry, batchID, challenge string, exp int64, returned []BatchEntry, now time.Time) error {
	if len(returned) != len(requested) {
		return fmt.Errorf("the server returned %d operations, %d were requested", len(returned), len(requested))
	}
	if left := exp - now.Unix(); left <= 0 || left > batchTTLSeconds+batchClockSkew {
		return fmt.Errorf("the batch expires in %d s, outside the %d s an approval may last", left, batchTTLSeconds)
	}
	want := make(map[string]BatchEntry, len(requested))
	for _, e := range requested {
		want[e.Key()] = e
	}
	for i, e := range returned {
		if i > 0 {
			p := returned[i-1]
			if p.Handle > e.Handle || (p.Handle == e.Handle && p.Operation >= e.Operation) {
				return fmt.Errorf("the server's list is not in canonical order at entry %d", i)
			}
		}
		r, ok := want[e.Key()]
		if !ok {
			return fmt.Errorf("the server returned an operation that was not requested: %s", e.Key())
		}
		if e.MeasurementDigest != r.MeasurementDigest || e.PolicyVersion != r.PolicyVersion {
			return fmt.Errorf("the server changed what %s binds", e.Key())
		}
		if e.Nonce == "" {
			return fmt.Errorf("the server gave %s no nonce", e.Key())
		}
		if e.VaultOp != computeVaultOp(r.Handle, r.MeasurementDigest, r.PolicyVersion, e.Nonce, exp) {
			return fmt.Errorf("the vault_op of %s does not match the operation", e.Key())
		}
	}
	if batchID != computeBatchID(label, exp, returned) {
		return errors.New("the batch id does not match the list")
	}
	got, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(challenge, "="))
	id, _ := base64.RawURLEncoding.DecodeString(batchID)
	if err != nil || len(id) == 0 || !bytes.Equal(got, id) {
		return errors.New("the approval's challenge is not the batch id")
	}
	return nil
}

// BeginBatch asks the identity provider to open a batch and verifies its
// answer. It returns ErrBatchUnavailable when the endpoints do not exist yet.
// audience is the aud of every token the batch yields ("" = the identity
// provider's default).
func BeginBatch(ctx context.Context, issuer, bearer, label, audience string, entries []BatchEntry) (*Batch, error) {
	issuer = strings.TrimRight(issuer, "/")
	begin := map[string]interface{}{"label": label, "ttl_seconds": batchTTLSeconds, "entries": entries}
	if audience != "" {
		begin["audience"] = audience
	}
	body, err := json.Marshal(begin)
	if err != nil {
		return nil, err
	}
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
	switch {
	// This route answers 404 itself for an owner with no credential.
	case resp.StatusCode == http.StatusNotFound && bytes.Contains(data, []byte("no credentials")):
		return nil, fmt.Errorf("batch begin: %s", data)
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return nil, ErrBatchUnavailable
	case resp.StatusCode == http.StatusBadRequest:
		// The server says what it refused (a label or handle it will not sign).
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &refusal) == nil && refusal.Error != "" {
			return nil, fmt.Errorf("the identity provider refused the batch: %s", refusal.Error)
		}
		return nil, fmt.Errorf("the identity provider refused the batch: %s", data)
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("batch begin -> %d: %s", resp.StatusCode, data)
	}
	var out struct {
		BatchID   string `json:"batch_id"`
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
		Exp              int64        `json:"exp"`
		Entries          []BatchEntry `json:"entries"`
		PushRegistered   *bool        `json:"push_registered"`
		ApprovalDeeplink string       `json:"approval_deeplink"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("batch begin: %w", err)
	}
	if err := verifyBatch(label, entries, out.BatchID, out.PublicKey.Challenge, out.Exp, out.Entries, time.Now()); err != nil {
		return nil, fmt.Errorf("refusing the batch: %w", err)
	}
	return &Batch{ID: out.BatchID, Label: label, Exp: out.Exp, Entries: out.Entries,
		PushRegistered: out.PushRegistered, Deeplink: out.ApprovalDeeplink}, nil
}

// ShowBatch tells the owner how to approve: the wallet is the only path, since
// the browser page approves one operation at a time.
func ShowBatch(out io.Writer, b *Batch) {
	fmt.Fprintf(out, "\nOne approval covers these %d operations: %s\n\n", len(b.Entries), b.Label)
	// A batch cannot be discovered without its id, so a lost push would leave
	// the owner with nothing: the QR is always shown.
	link := b.Deeplink
	if !batchDeeplink.MatchString(link) {
		link = "privasys-wallet://vault-approvals?batch_id=" + b.ID
	}
	if qr, err := qrcode.New(link, qrcode.Low); err == nil {
		fmt.Fprintln(out, qr.ToSmallString(false))
	}
	fmt.Fprintf(out, "  Link: %s\n\n", link)
	if b.PushRegistered != nil && !*b.PushRegistered {
		fmt.Fprint(out, "  Scan the QR with your phone's camera; it opens the Privasys Wallet.\n"+
			"  This account has no wallet registered for push, so no notification is coming.\n\n")
	} else {
		fmt.Fprint(out, "  Privasys Wallet: tap the \"Vault approval\" push, or scan the QR with your phone's camera.\n\n")
	}
	fmt.Fprintln(out, "Waiting for approval…")
}

// CollectBatchTokens polls until the owner approves the batch, then returns one
// verified token per entry, keyed by BatchEntry.Key.
func CollectBatchTokens(ctx context.Context, issuer, bearer string, b *Batch) (map[string]string, error) {
	u := strings.TrimRight(issuer, "/") + "/fido2/vault-approval/batch/token?challenge=" + url.QueryEscape(b.ID)
	deadline := time.Unix(b.Exp, 0).Add(15 * time.Second)
	for {
		tokens, pending, err := pollBatchToken(ctx, u, bearer)
		if err != nil {
			return nil, err
		}
		if !pending {
			return verifyBatchTokens(b, tokens)
		}
		if time.Now().After(deadline) {
			return nil, errors.New("no approval arrived before the batch expired; a wallet too old for batches never shows it: update the wallet, or use --one-by-one")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

type batchToken struct {
	Operation   string `json:"operation"`
	Handle      string `json:"handle"`
	VaultOp     string `json:"vault_op"`
	AccessToken string `json:"access_token"`
}

// pollBatchToken treats a dropped connection as still pending: the tokens can
// be collected only once, so one network error must not abandon an approval.
func pollBatchToken(ctx context.Context, u, bearer string) ([]batchToken, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusAccepted {
		return nil, true, nil
	}
	if isDeclined(resp.StatusCode, data) {
		return nil, false, ErrDeclined
	}
	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("batch token -> %d", resp.StatusCode)
	}
	var out struct {
		Tokens []batchToken `json:"tokens"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, false, errors.New("batch token: unreadable response")
	}
	return out.Tokens, false, nil
}

// verifyBatchTokens checks that there is exactly one token per entry and that
// each carries that entry's binding. The vaults verify the signature.
func verifyBatchTokens(b *Batch, tokens []batchToken) (map[string]string, error) {
	if len(tokens) != len(b.Entries) {
		return nil, fmt.Errorf("the identity provider issued %d tokens for %d operations", len(tokens), len(b.Entries))
	}
	byKey := make(map[string]batchToken, len(tokens))
	for _, t := range tokens {
		byKey[t.Operation+" "+t.Handle] = t
	}
	out := make(map[string]string, len(b.Entries))
	for _, e := range b.Entries {
		t, ok := byKey[e.Key()]
		if !ok {
			return nil, fmt.Errorf("no token was issued for %s", e.Key())
		}
		claims, err := tokenClaims(t.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("the token for %s: %w", e.Key(), err)
		}
		if t.VaultOp != e.VaultOp || claims.VaultOp != e.VaultOp || claims.Nonce != e.Nonce || claims.Exp != b.Exp {
			return nil, fmt.Errorf("the token for %s does not bind that operation", e.Key())
		}
		out[e.Key()] = t.AccessToken
	}
	return out, nil
}

type batchTokenClaims struct {
	VaultOp string `json:"vault_op"`
	Nonce   string `json:"nonce"`
	Exp     int64  `json:"exp"`
}

func tokenClaims(jwt string) (*batchTokenClaims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("unreadable claims")
	}
	var c batchTokenClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("unreadable claims")
	}
	return &c, nil
}
