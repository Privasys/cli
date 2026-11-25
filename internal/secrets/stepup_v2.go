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
	NewPolicy     json.RawMessage  // update_policy(_from): the full new policy
	// CurrentPolicy is the policy being replaced, exactly as GetPolicyRaw
	// returned it from the members: update_policy_from only (formats §5.3).
	CurrentPolicy json.RawMessage
	// TTLSeconds is how long a delete_after stays valid: what the migration or
	// upgrade can realistically take, at most 24 hours. Zero is privasys.id's
	// default of an hour. A shorter one fails safe: the old key then expires
	// by itself. Refused on every other operation.
	TTLSeconds int64
	// SuccessorHandle is the key that replaces Handle, on a delete_after whose
	// successor already exists (formats §9.2, created successor). Its target
	// is DeleteAfterTarget(SuccessorHandle, "-") and it lives at most
	// successorDeleteMaxTTL.
	SuccessorHandle string
	Audience   string // "" = privasys.id's default
	Context    approvalContext
}

// deleteAfterDefaultTTL is privasys.id's lifetime for a delete_after that asks
// for none.
const deleteAfterDefaultTTL = 3600

// successorDeleteMaxTTL bounds a delete_after whose successor exists already:
// nothing waits, so it gets no long lifetime.
const successorDeleteMaxTTL = 600

// singleBeginTTL is the lifetime a single v2 begin asks privasys.id for.
const singleBeginTTL = 300

// maxLeft is the longest an approval for a may have left when privasys.id
// answers: what was asked for a delete_after, else the operation's limit.
func (a ApprovalV2) maxLeft() int64 {
	if a.Operation != vault.BindDeleteAfter {
		return a.Operation.MaxTTLSeconds()
	}
	if a.SuccessorHandle != "" {
		if a.TTLSeconds == 0 {
			return singleBeginTTL
		}
		return a.TTLSeconds
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
	if err := a.checkPolicies(); err != nil {
		return err
	}
	if a.TTLSeconds != 0 {
		if a.Operation != vault.BindDeleteAfter {
			return fmt.Errorf("only a delete_after chooses its lifetime, not a %s", a.Operation)
		}
		if a.TTLSeconds < minApprovalLeftSeconds || a.TTLSeconds > vault.DeleteAfterMaxTTLSeconds {
			return fmt.Errorf("a delete_after lasts %d to %d s", minApprovalLeftSeconds, vault.DeleteAfterMaxTTLSeconds)
		}
	}
	if a.SuccessorHandle != "" {
		if a.Operation != vault.BindDeleteAfter {
			return fmt.Errorf("only a delete_after names a successor, not a %s", a.Operation)
		}
		if a.SuccessorHandle == a.Handle {
			return errors.New("a key cannot be its own successor")
		}
		if a.TTLSeconds > successorDeleteMaxTTL {
			return fmt.Errorf("a delete_after whose successor exists lasts at most %d s", successorDeleteMaxTTL)
		}
		want, err := vault.DeleteAfterTarget(a.SuccessorHandle, "-")
		if err != nil {
			return err
		}
		if a.Target != want {
			return errors.New("the target of a delete_after is not computed from its successor")
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
	if a.Operation == vault.BindDeleteAfter && a.SuccessorHandle == "" {
		return "", errors.New("a delete_after is approved alone only once its successor exists; otherwise in a batch with its successor's promote or creation")
	}
	if err := a.check(); err != nil {
		return "", err
	}
	ttl := int64(singleBeginTTL)
	if a.SuccessorHandle != "" && a.TTLSeconds != 0 {
		ttl = a.TTLSeconds
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
		"ttl_seconds":       ttl,
		"context":           a.Context,
	}
	if len(a.NewPolicy) != 0 {
		begin["new_policy"] = a.NewPolicy
	}
	if len(a.CurrentPolicy) != 0 {
		begin["current_policy"] = a.CurrentPolicy
	}
	if a.SuccessorHandle != "" {
		begin["successor_handle"] = a.SuccessorHandle
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

// UpdatePolicyApproval builds the approval of newPolicy (as given) replacing
// currentPolicy (as GetPolicyRaw returned it from the members) on handle, with
// the target computed here from the policies. Where every member advertises
// update_policy_from (formats §5.3), it is that form, which also binds the
// policy replaced; otherwise update_policy.
func UpdatePolicyApproval(handle string, policyVersion uint64, ids []PinnedIdentity, newPolicy, currentPolicy json.RawMessage,
	audience string, context map[string]string) (ApprovalV2, error) {
	a := ApprovalV2{Operation: vault.BindUpdatePolicy, Handle: handle, PolicyVersion: policyVersion,
		Identities: ids, NewPolicy: newPolicy, Audience: audience, Context: context}
	newPD, err := vault.PolicyDigestJSON(newPolicy)
	if err != nil {
		return ApprovalV2{}, fmt.Errorf("the new policy: %w", err)
	}
	a.Target = newPD
	if UpdatePolicyFromOn(ids) {
		curPD, err := vault.PolicyDigestJSON(currentPolicy)
		if err != nil {
			return ApprovalV2{}, fmt.Errorf("the current policy: %w", err)
		}
		if a.Target, err = vault.UpdatePolicyFromTarget(curPD, newPD); err != nil {
			return ApprovalV2{}, err
		}
		a.Operation, a.CurrentPolicy = vault.BindUpdatePolicyFrom, currentPolicy
	}
	return a, a.check()
}

// UpdatePolicyFromOn says every member advertises update_policy_from.
func UpdatePolicyFromOn(ids []PinnedIdentity) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !id.Has(vault.CapabilityUpdatePolicyFrom) {
			return false
		}
	}
	return true
}

// checkPolicies checks the policies an approval carries and that its target
// is computed from them: PD(new) for update_policy, and
// H("privasys-update-policy-from-v1\n" PD(current) "\n" PD(new)) for
// update_policy_from. Any other operation carries none.
func (a ApprovalV2) checkPolicies() error {
	switch a.Operation {
	case vault.BindUpdatePolicy, vault.BindUpdatePolicyFrom:
		if len(a.NewPolicy) == 0 {
			return errors.New("a policy update names no new policy")
		}
		pd, err := vault.PolicyDigestJSON(a.NewPolicy)
		if err != nil {
			return err
		}
		want := pd
		if a.Operation == vault.BindUpdatePolicyFrom {
			if len(a.CurrentPolicy) == 0 {
				return errors.New("an update_policy_from names no current policy")
			}
			cur, err := vault.PolicyDigestJSON(a.CurrentPolicy)
			if err != nil {
				return fmt.Errorf("the current policy: %w", err)
			}
			if want, err = vault.UpdatePolicyFromTarget(cur, pd); err != nil {
				return err
			}
		} else if len(a.CurrentPolicy) != 0 {
			return errors.New("an update_policy carries no current policy")
		}
		if a.Target != want {
			return errors.New("the target of a policy update is not computed from its policies")
		}
		return nil
	}
	if len(a.NewPolicy) != 0 || len(a.CurrentPolicy) != 0 {
		return fmt.Errorf("a %s carries no policy", a.Operation)
	}
	return nil
}

// DeleteAfterSuccessorApproval builds the delete_after of old, whose
// successor already exists (formats §9.2, created successor), with the target
// computed here from the successor.
func DeleteAfterSuccessorApproval(old, successor string, policyVersion uint64, ids []PinnedIdentity,
	audience string, context map[string]string) (ApprovalV2, error) {
	target, err := vault.DeleteAfterTarget(successor, "-")
	if err != nil {
		return ApprovalV2{}, err
	}
	a := ApprovalV2{Operation: vault.BindDeleteAfter, Handle: old, SuccessorHandle: successor, Target: target,
		PolicyVersion: policyVersion, Identities: ids, Audience: audience, Context: context}
	return a, a.check()
}
