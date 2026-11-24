// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Privasys/enclave-vaults-client/go/vault"
	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// policyKey is where a key whose policy is changing lives, as the CLI finds it.
type policyKey struct {
	Handle, MRENCLAVE, AttServer, Audience string
	Endpoints                              []string
}

// policyKeyFor finds the key's constellation: the one the control plane names,
// else the app's vault-export target (its key's home).
func policyKeyFor(ctx context.Context, client *api.Client, appID string, pa *api.PolicyApproval) (*policyKey, error) {
	if pa.ConstellationID != "" {
		d, err := client.VaultDirectoryAt(ctx, pa.ConstellationID)
		if err != nil {
			return nil, fmt.Errorf("find the key's vaults: %w", err)
		}
		return &policyKey{Handle: pa.Handle, MRENCLAVE: d.MRENCLAVE, AttServer: d.AttestationServer,
			Audience: d.OIDCAudience, Endpoints: d.Endpoints}, nil
	}
	tgt, err := client.GetVaultExportTarget(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("find the key's vaults: %w", err)
	}
	if tgt.Handle != pa.Handle {
		return nil, fmt.Errorf("the approval is for key %s, but the app's key is %s", pa.Handle, tgt.Handle)
	}
	return &policyKey{Handle: tgt.Handle, MRENCLAVE: tgt.MRENCLAVE, AttServer: tgt.AttestationServer,
		Audience: tgt.OIDCAudience, Endpoints: tgt.Endpoints}, nil
}

// checkPolicyApproval checks the control plane's request against what the
// CLI read from the key's vaults itself, before anything is shown to the
// owner: binding v2, the same members, the current policy version, and a
// target that is the digest of the exact new policy.
func checkPolicyApproval(pa *api.PolicyApproval, binding int, members []string, policyVersion uint64) error {
	if pa.Operation != string(vault.BindUpdatePolicy) {
		return fmt.Errorf("the control plane asks for a %q approval; only %s is supported", pa.Operation, vault.BindUpdatePolicy)
	}
	if pa.BindingVersion != 2 || binding != 2 {
		return fmt.Errorf("the control plane asks for binding %d, the key's vaults take binding %d", pa.BindingVersion, binding)
	}
	if pa.PolicyVersion != policyVersion {
		return fmt.Errorf("the control plane names policy version %d, the key's vaults hold version %d", pa.PolicyVersion, policyVersion)
	}
	read := append([]string(nil), members...)
	sent := append([]string(nil), pa.Members...)
	sort.Strings(read)
	sort.Strings(sent)
	if strings.Join(read, ",") != strings.Join(sent, ",") {
		return errors.New("the control plane names other vaults than the key's constellation has")
	}
	pd, err := vault.PolicyDigestJSON(pa.NewPolicy)
	if err != nil {
		return fmt.Errorf("the new policy: %w", err)
	}
	if !strings.EqualFold(pd, pa.Target) {
		return errors.New("the approval's target is not the digest of the new policy")
	}
	return nil
}

// approvePolicyChange asks the owner to approve the policy change the control
// plane answered 428 for, after checking it against the key's vaults, and
// returns the approval token. what names the change for the wallet.
func approvePolicyChange(cmd *cobra.Command, env *Env, client *api.Client, appID string, pa *api.PolicyApproval, what string,
	semantic func(ctx context.Context, current, proposed json.RawMessage, canon secrets.Canonicaliser) error) (string, error) {
	ctx := cmd.Context()
	if semantic == nil {
		return "", errors.New("no check of what this policy change does")
	}
	key, err := policyKeyFor(ctx, client, appID, pa)
	if err != nil {
		return "", err
	}
	audience, err := vaultApprovalAudience(key.Audience)
	if err != nil {
		return "", err
	}
	if pa.Audience != "" && pa.Audience != audience {
		return "", fmt.Errorf("the control plane asks for audience %q, the key's vaults accept %q", pa.Audience, audience)
	}
	vaultTok, err := auth.VaultTokenFor(ctx, env.Cfg.Issuer, audience)
	if err != nil {
		return "", err
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	binding, ids, policyVersion, err := secrets.KeyApproval(ctx, secrets.KeyTarget{Handle: key.Handle, Endpoints: key.Endpoints,
		MRENCLAVE: key.MRENCLAVE, AttServer: key.AttServer, AttToken: attTok, Bearer: vaultTok}, vault.OpUpdatePolicy)
	if err != nil {
		return "", err
	}
	members := make([]string, len(ids))
	for i, id := range ids {
		members[i] = id.MemberID()
	}
	if err := checkPolicyApproval(pa, binding, members, uint64(policyVersion)); err != nil {
		return "", fmt.Errorf("refusing the policy change: %w", err)
	}
	// What the change does, checked against the policy read from every member
	// (they must agree), not against anything the control plane says.
	dir := &api.VaultDirectory{Endpoints: key.Endpoints, MRENCLAVE: key.MRENCLAVE, AttestationServer: key.AttServer}
	current, curVersion, err := secrets.CurrentPolicy(ctx, dir, vaultTok, attTok, key.Handle)
	if err != nil {
		return "", err
	}
	if uint64(curVersion) != pa.PolicyVersion {
		return "", fmt.Errorf("refusing the policy change: the key's vaults hold policy version %d, the change is for %d", curVersion, pa.PolicyVersion)
	}
	if err := semantic(ctx, current, pa.NewPolicy, secrets.VaultCanonicaliser(dir, vaultTok, attTok)); err != nil {
		return "", fmt.Errorf("refusing the policy change: %w", err)
	}
	bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return "", err
	}
	actx := map[string]string{"app_id": appID, "change": what}
	if name := appFriendlyName(ctx, client, appID); name != "" {
		actx["app_name"] = name
	}
	approval, err := secrets.UpdatePolicyApproval(pa.Handle, pa.PolicyVersion, ids, pa.NewPolicy, audience, actx)
	if err != nil {
		return "", fmt.Errorf("refusing the policy change: %w", err)
	}
	tok, err := secrets.RequestApprovalV2(ctx, env.Cfg.Issuer, bearer, approval, secrets.OpenBrowser, cmd.ErrOrStderr())
	if errors.Is(err, secrets.ErrDeclined) {
		return "", fmt.Errorf("%w: the policy was not changed", err)
	}
	return tok, err
}

// policyChangeError explains a refused policy change.
func policyChangeError(err error) error {
	switch api.PolicyChangeCode(err) {
	case "policy_approval_stale":
		return fmt.Errorf("the key's policy changed after your approval; nothing was changed, run the command again: %w", err)
	case "policy_diverged":
		return fmt.Errorf("the key's vaults hold different policies; nothing was changed: %w", err)
	case "policy_not_lossless":
		return fmt.Errorf("the key's policy has fields the control plane does not know, so it refuses to rewrite it; nothing was changed: %w", err)
	case "policy_refused":
		return fmt.Errorf("the key's vaults refuse the new policy; nothing was changed: %w", err)
	}
	return err
}
