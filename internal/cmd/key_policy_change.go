// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Privasys/enclave-vaults-client/go/vault"
	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// keyPolicyChange is one change to an app data key's policy: what the
// owner's card says, the policy it must produce from the current one, and the
// control-plane call that makes it (newPolicy set only after a binding-v2
// approval of exactly those bytes).
type keyPolicyChange struct {
	summary string
	expect  func(current json.RawMessage) (json.RawMessage, error)
	call    func(c *api.Client, newPolicy json.RawMessage) (map[string]interface{}, error)
}

// changeKeyPolicy makes a policy change on an app's data key, with whatever
// approval the key's own UpdatePolicy rule asks for, read from every vault:
//   - a v1 step-up (keys from before binding v2, as in production): one
//     "policy-update" approval in the wallet, used at once as the bearer;
//   - binding v2: the control plane's 428, approved for the exact new policy;
//   - no step-up: the call as it is.
func changeKeyPolicy(cmd *cobra.Command, env *Env, client *api.Client, appID string, ch keyPolicyChange) (map[string]interface{}, error) {
	ctx := cmd.Context()
	tgt, err := client.GetVaultExportTarget(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("find the app's data key: %w", err)
	}
	audience, err := vaultApprovalAudience(tgt.OIDCAudience)
	if err != nil {
		return nil, err
	}
	vaultTok, err := auth.VaultTokenFor(ctx, env.Cfg.Issuer, audience)
	if err != nil {
		return nil, err
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	t := secrets.KeyTarget{Handle: tgt.Handle, Endpoints: tgt.Endpoints, MRENCLAVE: tgt.MRENCLAVE,
		AttServer: tgt.AttestationServer, AttToken: attTok, Bearer: vaultTok}
	rule, err := secrets.ReadPolicyRule(ctx, t, vault.OpUpdatePolicy)
	if err != nil {
		return nil, err
	}
	if rule.Readable && rule.Binding == 1 {
		return changeKeyPolicyV1(cmd, env, client, appID, tgt, audience, vaultTok, attTok, rule.Version, ch)
	}
	res, err := ch.call(client, nil)
	if pa, need := api.PolicyApprovalFrom(err); need {
		tok, aerr := approvePolicyChange(cmd, env, client, appID, pa, ch.summary,
			func(ctx context.Context, current, proposed json.RawMessage, canon secrets.Canonicaliser) error {
				expected, err := ch.expect(current)
				if err != nil {
					return err
				}
				same, err := secrets.SameStoredPolicy(ctx, canon, expected, proposed)
				if err != nil {
					return err
				}
				if !same {
					return fmt.Errorf("the requested change does more than this: %s", ch.summary)
				}
				return nil
			})
		if aerr != nil {
			return nil, aerr
		}
		sc := *client
		sc.Token = tok
		res, err = ch.call(&sc, pa.NewPolicy)
	}
	if err != nil {
		return nil, policyChangeError(err)
	}
	return res, nil
}

// changeKeyPolicyV1 makes the change on a key whose UpdatePolicy rule asks
// for a v1 step-up. That approval is not bound to the change, so the control
// plane computes the new policy: the change is checked against the current
// policy before the tap, and what the vaults then hold is read back and
// compared with what was asked.
func changeKeyPolicyV1(cmd *cobra.Command, env *Env, client *api.Client, appID string, tgt *api.VaultExportTarget,
	audience, vaultTok, attTok string, version uint32, ch keyPolicyChange) (map[string]interface{}, error) {
	ctx := cmd.Context()
	dir := &api.VaultDirectory{Endpoints: tgt.Endpoints, MRENCLAVE: tgt.MRENCLAVE, AttestationServer: tgt.AttestationServer}
	current, curVersion, err := secrets.CurrentPolicy(ctx, dir, vaultTok, attTok, tgt.Handle)
	if err != nil {
		return nil, err
	}
	if curVersion != version {
		return nil, errors.New("the key's policy changed while it was being read; run the command again")
	}
	expected, err := ch.expect(current)
	if err != nil {
		return nil, err
	}
	bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return nil, err
	}
	actx := map[string]string{"app_id": appID, "summary": ch.summary, "change": ch.summary}
	if name := appFriendlyName(ctx, client, appID); name != "" {
		actx["app_name"] = name
	}
	if info, ierr := secrets.KeyInfoAt(ctx, dir, vaultTok, attTok, tgt.Handle); ierr == nil && info.KeyType != "" {
		actx["key_type"] = string(info.KeyType)
	}
	// One approval for this one change, used at once: the vault takes it
	// for 300 s from its issue.
	tok, err := secrets.RequestStepUpViaBrowserFor(ctx, env.Cfg.Issuer, bearer, audience, "policy-update",
		tgt.Handle, "", version, actx, secrets.OpenBrowser, cmd.ErrOrStderr())
	if errors.Is(err, secrets.ErrDeclined) {
		return nil, fmt.Errorf("%w: the policy was not changed", err)
	}
	if err != nil {
		return nil, err
	}
	sc := *client
	sc.Token = tok
	res, err := ch.call(&sc, nil)
	if err != nil {
		return nil, policyChangeError(err)
	}
	if res == nil {
		res = map[string]interface{}{}
	}
	// What the vaults hold now must be what was asked.
	fresh, err := auth.VaultTokenFor(ctx, env.Cfg.Issuer, audience)
	if err != nil {
		return res, fmt.Errorf("changed, but the result could not be checked: %w", err)
	}
	now, _, err := secrets.CurrentPolicy(ctx, dir, fresh, attTok, tgt.Handle)
	if err != nil {
		return res, fmt.Errorf("changed, but the result could not be read back: %w", err)
	}
	same, err := secrets.SameStoredPolicy(ctx, secrets.VaultCanonicaliser(dir, fresh, attTok), expected, now)
	if err != nil {
		return res, fmt.Errorf("changed, but the result could not be compared: %w", err)
	}
	if !same {
		return res, fmt.Errorf("WARNING: the key's vaults now hold a policy that differs from what was asked (%s); check it with `privasys apps measurements %s` and tell Privasys", ch.summary, appID)
	}
	res["checked"] = "the vaults hold exactly the policy asked for"
	return res, nil
}

// refuseRunningProfile refuses, before any approval, to retire the profile
// the app is running on, as the control plane's /measurements marks it
// (running_profile). An older control plane without the mark is left to
// refuse it itself.
func refuseRunningProfile(cmd *cobra.Command, client *api.Client, appID string, p api.RetiredProfile) error {
	m, err := client.AppMeasurements(cmd.Context(), appID)
	if err != nil {
		return nil
	}
	list, _ := m["measurements"].([]interface{})
	eq := func(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) }
	for _, x := range list {
		e, _ := x.(map[string]interface{})
		s := func(k string) string { v, _ := e[k].(string); return v }
		if eq(s("workload_digest"), p.WorkloadDigest) && eq(s("mrtd"), p.MRTD) && eq(s("rtmr1"), p.RTMR1) && eq(s("rtmr2"), p.RTMR2) {
			if running, _ := e["running_profile"].(bool); running {
				return errors.New("that is the profile the app is running on; it cannot be retired")
			}
		}
	}
	return nil
}

// requireRetireMode refuses, before any approval, a retire the control plane
// would make differently from what the CLI checks: it must list mode in
// /measurements' retire_modes ("digest_all": every profile of a build in one
// update; "profile": exactly one profile). Older control planes remove one
// profile per call and list nothing.
func requireRetireMode(cmd *cobra.Command, client *api.Client, appID, mode string) error {
	m, err := client.AppMeasurements(cmd.Context(), appID)
	if err != nil {
		return fmt.Errorf("read the app's measurements: %w", err)
	}
	modes, _ := m["retire_modes"].([]interface{})
	for _, x := range modes {
		if s, _ := x.(string); s == mode {
			return nil
		}
	}
	return errors.New("this control plane retires measurements another way than this CLI checks (it does not list retire mode " +
		mode + "); nothing was changed. Update the control plane first, or use an older CLI")
}
