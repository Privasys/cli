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
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/ratls"
	"github.com/Privasys/cli/internal/secrets"
)

func newKeyPolicyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "key-policy",
		Short: "Change the policy of a key you own directly on its vaults",
		Long: `For keys the platform has no command for, such as a machine's data key or
an app's registry credential: the change is made on the key's vaults
themselves, with your approval in the Privasys Wallet when the key's policy
asks for it. The approval goes to the vaults only, never to the control plane.

Every vault must hold the same policy before anything changes. After the
change each vault is read back. If some vaults took it and others did not,
running the same command again finishes the change on the others only.`,
	}
	c.AddCommand(newKeyPolicyRetireRuntimeCmd(), newKeyPolicyTCBCmd())
	return c
}

func newKeyPolicyRetireRuntimeCmd() *cobra.Command {
	var enclaveID, host, mrtd, rtmr1, rtmr2 string
	var yes bool
	cmd := &cobra.Command{
		Use:   "retire-runtime <key-handle> --enclave <id> --host <fqdn> --mrtd <hex> --rtmr1 <hex> --rtmr2 <hex>",
		Short: "Stop releasing a key to an older machine runtime",
		Long: `Removes every profile of the key on the runtime named by --mrtd, --rtmr1 and
--rtmr2, whatever build it names.

The runtime the machine runs now is never removed. It is read from the
machine's own attestation (a fresh RA-TLS quote from --host, verified) and from
the control plane's record for --enclave; they must agree.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := secrets.Runtime{MRTD: mrtd, RTMR1: rtmr1, RTMR2: rtmr2}
			if !r.Complete() || enclaveID == "" || host == "" {
				return fmt.Errorf("pass --enclave, --host, --mrtd, --rtmr1 and --rtmr2")
			}
			env, client, err := keyPolicyEnv(cmd)
			if err != nil {
				return err
			}
			handle := args[0]
			// The machine whose runtime is protected must be the one this key is
			// for: the attested host must carry the workload id the key pins, and
			// a machine's data key is named after its enclave.
			precheck := func(current json.RawMessage) error {
				id, err := secrets.KeyWorkloadID(current)
				if err != nil {
					return err
				}
				if strings.Contains(handle, "/manager/data/") && !strings.Contains(handle, "/"+strings.ReplaceAll(strings.ToLower(enclaveID), "-", "")+"/manager/data/") {
					return fmt.Errorf("%s is not the data key of enclave %s", handle, enclaveID)
				}
				running, oids, err := runningRuntime(cmd, env, client, enclaveID, host)
				if err != nil {
					return err
				}
				if !secrets.CertCarries(oids, secrets.OIDWorkloadID, id) {
					return fmt.Errorf("%s does not attest the workload this key is for (%s); nothing was changed", host, id)
				}
				if running.Equal(r) {
					return fmt.Errorf("that is the runtime the machine runs now; it cannot be retired")
				}
				return nil
			}
			summary := "Stop releasing this key to the machine runtime with RTMR1 " + truncHex(rtmr1)
			return directKeyPolicyChange(cmd, env, client, handle, summary, yes,
				func(cur json.RawMessage) (json.RawMessage, error) { return secrets.ExpectRetireRuntime(cur, r) }, precheck)
		},
	}
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "the machine's enclave id (its recorded measurement)")
	cmd.Flags().StringVar(&host, "host", "", "a host served by that machine, to read its live attestation")
	cmd.Flags().StringVar(&mrtd, "mrtd", "", "the runtime's MRTD (hex)")
	cmd.Flags().StringVar(&rtmr1, "rtmr1", "", "the runtime's RTMR1 (hex)")
	cmd.Flags().StringVar(&rtmr2, "rtmr2", "", "the runtime's RTMR2 (hex)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

func newKeyPolicyTCBCmd() *cobra.Command {
	var accept []string
	var strict, yes bool
	cmd := &cobra.Command{
		Use:   "tcb-policy <key-handle> (--accept <status> ... | --strict)",
		Short: "Set which Intel TCB statuses may unlock a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strict == (len(accept) > 0) {
				return fmt.Errorf("pass either --strict or one or more --accept <status>")
			}
			statuses := []string{}
			if !strict {
				statuses = accept
			}
			env, client, err := keyPolicyEnv(cmd)
			if err != nil {
				return err
			}
			summary := "Accept only the TCB floor for this key"
			if !strict {
				summary = "Accept the TCB floor plus " + strings.Join(statuses, ", ") + " for this key"
			}
			return directKeyPolicyChange(cmd, env, client, args[0], summary, yes,
				func(cur json.RawMessage) (json.RawMessage, error) { return secrets.ExpectTCBPolicy(cur, statuses) }, nil)
		},
	}
	cmd.Flags().StringArrayVar(&accept, "accept", nil, "a TCB status to accept beyond the floor (repeatable)")
	cmd.Flags().BoolVar(&strict, "strict", false, "accept only the floor (UpToDate, SWHardeningNeeded)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

func keyPolicyEnv(cmd *cobra.Command) (*Env, *api.Client, error) {
	env, err := loadEnv(cmd)
	if err != nil {
		return nil, nil, err
	}
	client, err := apiClient(cmd, env)
	return env, client, err
}

// runningRuntime is the runtime the machine runs now: from a fresh, verified
// RA-TLS quote of a host it serves, which must agree with the control plane's
// record of the machine.
func runningRuntime(cmd *cobra.Command, env *Env, client *api.Client, enclaveID, host string) (secrets.Runtime, map[string]string, error) {
	ctx := cmd.Context()
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	res, err := ratls.Verify(ctx, ratls.Params{Host: host, ServerName: host, Challenge: ratls.NewNonce(),
		AttServerURL: defaultAttServer, AttServerTok: attTok})
	if err != nil {
		return secrets.Runtime{}, nil, fmt.Errorf("attest %s: %w", host, err)
	}
	if !res.Verified {
		return secrets.Runtime{}, nil, fmt.Errorf("the attestation of %s did not verify: %s", host, res.VerifyError)
	}
	live, err := secrets.TDXRuntime(res.QuoteRaw)
	if err != nil {
		return secrets.Runtime{}, nil, fmt.Errorf("the quote of %s: %w", host, err)
	}
	rec, err := client.EnclaveMeasurements(ctx, enclaveID)
	if err != nil {
		return secrets.Runtime{}, nil, fmt.Errorf("the recorded measurement of %s: %w", enclaveID, err)
	}
	if !live.Equal(secrets.Runtime{MRTD: rec.MRTD, RTMR1: rec.RTMR1, RTMR2: rec.RTMR2}) {
		return secrets.Runtime{}, nil, errors.New("the machine's live attestation and its recorded measurement differ: the machine was rolled since the record, or the record is stale; nothing was changed")
	}
	oids := map[string]string{}
	for _, o := range res.CustomOIDs {
		oids[o.OID] = o.ValueHex
	}
	return live, oids, nil
}

// directKeyPolicyChange finds the key's vaults, plans the change from what
// every vault holds, takes the approval the key's rule asks for, applies it
// on the vaults that need it, and reads every vault back.
func directKeyPolicyChange(cmd *cobra.Command, env *Env, client *api.Client, handle, summary string, yes bool,
	expect func(json.RawMessage) (json.RawMessage, error), precheck func(json.RawMessage) error) error {
	ctx := cmd.Context()
	errOut := cmd.ErrOrStderr()
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	dir, audience, vaultTok, members, err := findKeyVaults(ctx, env, client, handle, attTok)
	if err != nil {
		return err
	}
	canon := secrets.VaultCanonicaliser(dir, vaultTok, attTok)
	plan, err := secrets.PlanDirectChange(ctx, members, expect, canon)
	if err != nil {
		return err
	}
	if len(plan.ToUpdate) == 0 {
		fmt.Fprintf(errOut, "Every vault of %s already holds this change.\n", dir.Name)
		return nil
	}
	if precheck != nil {
		if err := precheck(plan.Current); err != nil {
			return err
		}
	}
	if len(plan.Done) > 0 {
		fmt.Fprintf(errOut, "Finishing an earlier change: %s already hold it, %s do not.\n",
			strings.Join(plan.Done, ", "), strings.Join(plan.ToUpdate, ", "))
	}
	if !yes {
		ok, cErr := confirm(cmd, env, fmt.Sprintf("%s (%s, on %s)? [y/N] ", summary, handle, dir.Name))
		if cErr != nil {
			return cErr
		}
		if !ok {
			return fmt.Errorf("aborted")
		}
	}
	appr, err := directApproval(cmd, env, dir, handle, audience, vaultTok, attTok, plan, summary)
	if err != nil {
		return err
	}
	results := secrets.ApplyDirect(ctx, dir, attTok, handle, plan, appr)

	// Every vault is read back: what each holds now is the result.
	fresh, err := auth.VaultTokenFor(ctx, env.Cfg.Issuer, audience)
	if err != nil {
		return fmt.Errorf("changed, but the vaults could not be read back: %w", err)
	}
	after, rerr := secrets.ReadMemberPolicies(ctx, dir, fresh, attTok, handle)
	rows := [][]string{}
	out := []map[string]any{}
	allDone := rerr == nil
	for _, m := range after {
		state := "holds the change"
		if m.PD != plan.TargetPD {
			state = "does NOT hold the change"
			if e := results[m.Endpoint]; e != nil {
				state += ": " + e.Error()
			}
			allDone = false
		}
		rows = append(rows, []string{m.Endpoint, fmt.Sprintf("v%d", m.Version), state})
		out = append(out, map[string]any{"vault": m.Endpoint, "version": m.Version, "holds_change": m.PD == plan.TargetPD})
	}
	if err := output.Emit(env.Format, map[string]any{"handle": handle, "constellation": dir.Name, "vaults": out, "complete": allDone},
		func() output.Table { return output.Table{Headers: []string{"VAULT", "VERSION", "RESULT"}, Rows: rows} }); err != nil {
		return err
	}
	if rerr != nil {
		return fmt.Errorf("the vaults could not all be read back: %w", rerr)
	}
	if !allDone {
		return fmt.Errorf("the change is not on every vault; run the same command again to finish it")
	}
	return nil
}

// findKeyVaults finds the live constellation holding handle, where every
// member answers with its policy.
func findKeyVaults(ctx context.Context, env *Env, client *api.Client, handle, attTok string) (*api.VaultDirectory, string, string, []secrets.MemberPolicy, error) {
	cons, err := client.LiveVaultConstellations(ctx)
	if err != nil {
		return nil, "", "", nil, err
	}
	var lastErr error
	for _, c := range cons {
		d, derr := client.VaultDirectoryAt(ctx, c.ID)
		if derr != nil {
			lastErr = derr
			continue
		}
		audience, aerr := vaultApprovalAudience(d.OIDCAudience)
		if aerr != nil {
			lastErr = aerr
			continue
		}
		tok, terr := auth.VaultTokenFor(ctx, env.Cfg.Issuer, audience)
		if terr != nil {
			lastErr = terr
			continue
		}
		members, merr := secrets.ReadMemberPolicies(ctx, d, tok, attTok, handle)
		if merr != nil {
			lastErr = merr
			continue
		}
		return d, audience, tok, members, nil
	}
	return nil, "", "", nil, fmt.Errorf("no live constellation holds %s on every vault: %v", handle, lastErr)
}

// directApproval is the approval the key's own UpdatePolicy rule asks for,
// given to the vaults directly: none, a v1 "policy-update" step-up, or
// binding v2 (update_policy_from where every member takes it).
func directApproval(cmd *cobra.Command, env *Env, dir *api.VaultDirectory, handle, audience, vaultTok, attTok string,
	plan secrets.DirectPlan, summary string) (secrets.DirectApproval, error) {
	ctx := cmd.Context()
	var kp vault.KeyPolicy
	if err := json.Unmarshal(plan.Current, &kp); err != nil {
		return secrets.DirectApproval{}, fmt.Errorf("the key's policy: %w", err)
	}
	binding, err := secrets.BindingVersion(kp, vault.OpUpdatePolicy)
	if err != nil {
		return secrets.DirectApproval{}, err
	}
	actx := map[string]string{"summary": summary, "change": summary}
	bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return secrets.DirectApproval{}, err
	}
	switch binding {
	case 0:
		return secrets.DirectApproval{Bearer: vaultTok}, nil
	case 1:
		tok, err := secrets.RequestStepUpViaBrowserFor(ctx, env.Cfg.Issuer, bearer, audience, "policy-update",
			handle, "", plan.Version, actx, secrets.OpenBrowser, cmd.ErrOrStderr())
		if errors.Is(err, secrets.ErrDeclined) {
			return secrets.DirectApproval{}, fmt.Errorf("%w: the policy was not changed", err)
		}
		return secrets.DirectApproval{Bearer: tok}, err
	}
	ids, err := secrets.ConstellationIdentities(ctx, dir.Endpoints, dir.MRENCLAVE, dir.AttestationServer, attTok)
	if err != nil {
		return secrets.DirectApproval{}, fmt.Errorf("read the vaults' identities: %w", err)
	}
	a, err := secrets.UpdatePolicyApproval(handle, uint64(plan.Version), ids, plan.Target, plan.Current, audience, actx)
	if err != nil {
		return secrets.DirectApproval{}, err
	}
	tok, err := secrets.RequestApprovalV2(ctx, env.Cfg.Issuer, bearer, a, secrets.OpenBrowser, cmd.ErrOrStderr())
	if errors.Is(err, secrets.ErrDeclined) {
		return secrets.DirectApproval{}, fmt.Errorf("%w: the policy was not changed", err)
	}
	if err != nil {
		return secrets.DirectApproval{}, err
	}
	out := secrets.DirectApproval{Bearer: tok, BindingMembers: secrets.MemberIDs(ids)}
	if a.Operation == vault.BindUpdatePolicyFrom {
		pd, err := vault.PolicyDigestJSON(plan.Current)
		if err != nil {
			return secrets.DirectApproval{}, err
		}
		out.ReplacedPD = pd
	}
	return out, nil
}
