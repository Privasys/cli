// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

// Owner approvals on binding v2.
//
// A v2 approval names the constellation's member vaults, so it is spent only
// on the vaults it was made for. Update and delete are bound to their content.
// privasys.id sets the approver, the nonce and the expiry and returns the whole
// binding; the CLI rebuilds the text from what it asked for plus those three
// values, and refuses an answer that binds anything else.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// bindingClockSkew tolerates a difference between this machine's clock and privasys.id's.
const bindingClockSkew = 120

// minApprovalLeftSeconds: an approval with less time left would expire before
// the owner could tap it, so it is not shown.
const minApprovalLeftSeconds = 30

// ApprovalV2 is one operation to approve on binding v2.
//
// Identities must come from ReadPinnedIdentity: read from each member vault
// over its own RA-TLS connection with a pinned MRENCLAVE, never from the
// control plane, a file or a cache. They decide which vaults the approval is
// valid on, and checking them for consistency authenticates nothing.
type ApprovalV2 struct {
	Operation     vault.BindingOp
	Handle        string
	Target        string // as it stands in the binding; "" for none
	PolicyVersion uint64
	Identities    []PinnedIdentity // each member vault, read with ReadPinnedIdentity
	IssuerIndex   uint32           // the key's issuer entry that approves
	NewPolicy     json.RawMessage  // update_policy only: the full new policy
	// TTLSeconds is how long a delete_after stays valid: what the migration or
	// upgrade can realistically take, at most 24 hours. Zero is privasys.id's
	// default of an hour. A shorter one fails safe: the old key then expires
	// by itself. Refused on every other operation.
	TTLSeconds int64
	Audience   string // "" = privasys.id's default
	Context    approvalContext
}

// deleteAfterDefaultTTL is privasys.id's lifetime for a delete_after that asks
// for none.
const deleteAfterDefaultTTL = 3600

// maxLeft is the longest an approval for a may have left when privasys.id
// answers: what was asked for a delete_after, else the operation's limit.
func (a ApprovalV2) maxLeft() int64 {
	if a.Operation != vault.BindDeleteAfter {
		return a.Operation.MaxTTLSeconds()
	}
	if a.TTLSeconds == 0 {
		return deleteAfterDefaultTTL
	}
	return a.TTLSeconds
}

// approvalV2Answer is privasys.id's answer to a v2 begin.
type approvalV2Answer struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
	VaultOp string        `json:"vault_op"`
	Binding bindingAnswer `json:"binding"`
}

// bindingAnswer is a binding as privasys.id returns it.
type bindingAnswer struct {
	Members       []string `json:"members"`
	Op            string   `json:"op"`
	Handle        string   `json:"handle"`
	Target        string   `json:"target"`
	PolicyVersion uint64   `json:"policy_version"`
	Approver      string   `json:"approver"`
	HolderHead    string   `json:"holder_head"`
	Nonce         string   `json:"nonce"`
	Exp           int64    `json:"exp"`
}

func (a ApprovalV2) check() error {
	if a.Operation == vault.BindUpdatePolicy {
		if len(a.NewPolicy) == 0 {
			return errors.New("a policy update names no new policy")
		}
		pd, err := vault.PolicyDigestJSON(a.NewPolicy)
		if err != nil {
			return err
		}
		if a.Target != pd {
			return errors.New("the target of a policy update is not the digest of its new policy")
		}
	} else if len(a.NewPolicy) != 0 {
		return fmt.Errorf("a %s carries no new policy", a.Operation)
	}
	if a.TTLSeconds != 0 {
		if a.Operation != vault.BindDeleteAfter {
			return fmt.Errorf("only a delete_after chooses its lifetime, not a %s", a.Operation)
		}
		if a.TTLSeconds < minApprovalLeftSeconds || a.TTLSeconds > vault.DeleteAfterMaxTTLSeconds {
			return fmt.Errorf("a delete_after lasts %d to %d s", minApprovalLeftSeconds, vault.DeleteAfterMaxTTLSeconds)
		}
	}
	if len(a.Identities) == 0 {
		return errors.New("an approval must name the vaults it is for")
	}
	for _, id := range a.Identities {
		if err := id.id.CheckConsistent(); err != nil {
			return err
		}
	}
	return nil
}

// RequestApprovalV2 opens a v2 approval at privasys.id, verifies the binding it
// returns, shows the approval to the owner and returns the token once approved.
func RequestApprovalV2(ctx context.Context, issuer, bearer string, a ApprovalV2, open BrowserOpener, out io.Writer) (string, error) {
	if a.Operation == vault.BindDeleteAfter {
		return "", errors.New("a delete_after is approved only in a batch with its successor's promote or creation")
	}
	if err := a.check(); err != nil {
		return "", err
	}
	issuer = strings.TrimRight(issuer, "/")
	begin := map[string]interface{}{
		"binding_version": 2,
		"operation":       a.Operation,
		"handle":          a.Handle,
		"target":          orDash(a.Target),
		"policy_version":  a.PolicyVersion,
		"members":         a.members(),
		// The identities relayed untouched: the wallet verifies each quote,
		// and privasys.id checks members are their member ids.
		"member_identities": a.Identities,
		"issuer_index":      a.IssuerIndex,
		"ttl_seconds":       300,
		"context":           a.Context,
	}
	if len(a.NewPolicy) != 0 {
		begin["new_policy"] = a.NewPolicy
	}
	if a.Audience != "" {
		begin["audience"] = a.Audience
	}
	body, err := json.Marshal(begin)
	if err != nil {
		return "", err
	}
	answer, err := postBearer(ctx, issuer+"/fido2/vault-approval/begin", bearer, body)
	if err != nil {
		return "", fmt.Errorf("approval begin: %w", err)
	}
	b, vaultOp, err := verifyApprovalV2(a, answer, time.Now())
	if err != nil {
		return "", fmt.Errorf("refusing the approval: %w", err)
	}
	summary := map[string]string{"operation": string(a.Operation), "handle": a.Handle, "target": b.Target}
	tok, err := awaitApproval(ctx, issuer, bearer, string(a.Operation), answer, summary, a.Context, open, out)
	if err != nil {
		return "", err
	}
	claims, err := tokenClaims(tok)
	if err != nil {
		return "", fmt.Errorf("the approval token: %w", err)
	}
	if claims.VaultOp != vaultOp || claims.Nonce != b.Nonce || claims.Exp != b.Exp {
		return "", errors.New("the approval token does not bind the operation that was approved")
	}
	return tok, nil
}

// verifyApprovalV2 checks a single begin's answer: the binding, its vault_op,
// and the challenge being that vault_op.
func verifyApprovalV2(a ApprovalV2, answer []byte, now time.Time) (vault.BindingV2, string, error) {
	var ans approvalV2Answer
	if err := json.Unmarshal(answer, &ans); err != nil {
		return vault.BindingV2{}, "", errors.New("unreadable answer")
	}
	b, vaultOp, err := verifyBindingV2(a, ans.Binding, ans.VaultOp, now)
	if err != nil {
		return vault.BindingV2{}, "", err
	}
	if strings.TrimRight(ans.PublicKey.Challenge, "=") != vaultOp {
		return vault.BindingV2{}, "", errors.New("the challenge is not the operation's vault_op")
	}
	return b, vaultOp, nil
}

// verifyBindingV2 rebuilds the binding from what was asked plus the approver,
// nonce and expiry privasys.id chose, and checks the answer binds exactly that.
func verifyBindingV2(a ApprovalV2, got bindingAnswer, gotVaultOp string, now time.Time) (vault.BindingV2, string, error) {
	if !sameSet(got.Members, a.members()) {
		return vault.BindingV2{}, "", errors.New("the binding names other vaults than the ones asked for")
	}
	if got.Op != string(a.Operation) || got.Handle != a.Handle || got.Target != orDash(a.Target) || got.PolicyVersion != a.PolicyVersion {
		return vault.BindingV2{}, "", errors.New("the binding is for another operation than the one asked for")
	}
	prefix := "oidc:" + strconv.FormatUint(uint64(a.IssuerIndex), 10) + ":"
	if !strings.HasPrefix(got.Approver, prefix) || len(got.Approver) == len(prefix) {
		return vault.BindingV2{}, "", errors.New("the binding's approver is not an owner at the key's issuer")
	}
	if got.HolderHead != "-" {
		return vault.BindingV2{}, "", errors.New("an issuer approval names a holder record")
	}
	if n, err := base64.RawURLEncoding.DecodeString(got.Nonce); err != nil || len(n) != 16 {
		return vault.BindingV2{}, "", errors.New("the binding's nonce is not 16 bytes")
	}
	if left := got.Exp - now.Unix(); left < minApprovalLeftSeconds || left > a.maxLeft()+bindingClockSkew {
		return vault.BindingV2{}, "", fmt.Errorf("the approval expires in %d s, outside the %d s this %s approval may last", left, a.maxLeft(), a.Operation)
	}
	b := vault.BindingV2{
		Members: a.members(), Op: a.Operation, Handle: a.Handle, Target: a.Target,
		PolicyVersion: a.PolicyVersion, Approver: got.Approver, Nonce: got.Nonce, Exp: got.Exp,
	}
	vaultOp, err := b.VaultOp()
	if err != nil {
		return vault.BindingV2{}, "", err
	}
	if gotVaultOp != vaultOp {
		return vault.BindingV2{}, "", errors.New("the vault_op does not match the operation")
	}
	return b, vaultOp, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] || (i > 0 && x[i] == x[i-1]) {
			return false
		}
	}
	return true
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// members is the member id of each identity.
func (a ApprovalV2) members() []string {
	m := make([]string, len(a.Identities))
	for i, id := range a.Identities {
		m[i] = id.MemberID()
	}
	return m
}

// UpdatePolicyApproval builds the update_policy approval of newPolicy (as
// given) on handle, with the target computed here from the policy itself.
// Where every member advertises update_policy_from (formats §5.3), a plain
// update_policy is refused: those vaults' owners get the form that also binds
// the policy replaced, which this CLI does not ask privasys.id for yet.
func UpdatePolicyApproval(handle string, policyVersion uint64, ids []PinnedIdentity, newPolicy json.RawMessage,
	audience string, context map[string]string) (ApprovalV2, error) {
	if len(ids) > 0 {
		all := true
		for _, id := range ids {
			if !id.Has(vault.CapabilityUpdatePolicyFrom) {
				all = false
				break
			}
		}
		if all {
			return ApprovalV2{}, errors.New("the key's vaults take policy changes approved as update_policy_from, which this CLI cannot ask for yet; update the CLI")
		}
	}
	pd, err := vault.PolicyDigestJSON(newPolicy)
	if err != nil {
		return ApprovalV2{}, fmt.Errorf("the new policy: %w", err)
	}
	a := ApprovalV2{Operation: vault.BindUpdatePolicy, Handle: handle, Target: pd, PolicyVersion: policyVersion,
		Identities: ids, NewPolicy: newPolicy, Audience: audience, Context: context}
	return a, a.check()
}
