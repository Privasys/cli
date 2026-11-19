// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

// vaultQuorum is how many vaults must accept an operation.
const vaultQuorum = 2

func newEnclavesPromoteReleaseCmd() *cobra.Command {
	var release string
	var exclude []string
	var dryRun, oneByOne bool
	var parallel int
	cmd := &cobra.Command{
		Use:   "promote-release <enclave> --release <tag>",
		Short: "Approve every key on a host for a runtime release, with one approval",
		Long: `Before a host rolls to a new runtime release, every key on it must admit the
release's measurements. This stages each one for the release and promotes them
all under ONE wallet approval: the manager /data key, the key of every app on
the enclave, and their registry credentials.

The approval lasts 5 minutes from the moment it starts, so the promotes run in
parallel once you approve. The command exits non-zero unless every key was
promoted: do not swap the boot disk otherwise. After a partial failure it offers
a new approval for the keys left.

  --release     the release tag (or its https URL) the host is rolling to
  --dry-run     stage, then print the exact operations without asking for an
                approval. Staging authorises nothing on its own
  --one-by-one  one approval per key, as before. Used automatically when the
                identity provider does not offer batches yet
  --exclude     leave an app out, by name or id (repeatable). Its key will not
                admit the release, so that app will not start after the roll
  --parallel    how many stages or promotes run at once (default 4)

The default environment is production; pass --test for the test environment.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(release) == "" {
				return fmt.Errorf("--release <tag> is required")
			}
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			out := cmd.ErrOrStderr()
			enclave, err := resolveEnclave(ctx, client, args[0])
			if err != nil {
				return err
			}
			enclaveID, name := output.Str(enclave, "id"), output.Str(enclave, "name")
			if tee := output.Str(enclave, "tee_type"); tee != "" && !strings.EqualFold(tee, "tdx") {
				return fmt.Errorf("%s is a %s enclave: runtime releases apply to TDX hosts", name, tee)
			}
			fmt.Fprintf(out, "Platform: %s\nEnclave:  %s (%s)\nRelease:  %s\n", env.Cfg.Endpoint, name, enclaveID, release)
			targets, err := releaseTargets(ctx, client, enclaveID, name, release, exclude, out)
			if err != nil {
				return err
			}
			run := &approvalRun{
				Label:    releaseLabel(release, name),
				Issuer:   env.Cfg.Issuer,
				Targets:  targets,
				Parallel: parallel,
				DryRun:   dryRun,
				OneByOne: oneByOne,
				Bearer:   func(ctx context.Context) (string, error) { return auth.AccessToken(ctx, env.Cfg.Issuer) },
				Refresh: func(ctx context.Context) error {
					tok, err := auth.AccessToken(ctx, env.Cfg.Issuer)
					if err == nil {
						client.Token = tok
					}
					return err
				},
				Ask:  func(prompt string) (bool, error) { return confirm(cmd, env, prompt) },
				Open: secrets.OpenBrowser,
				Out:  out,
			}
			if err := run.Run(ctx); err != nil {
				return err
			}
			if dryRun {
				fmt.Fprintln(out, "\nStaged. Nothing was approved or promoted.")
				return nil
			}
			output.Success(out, "Every key on %s admits %s", name, release)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&release, "release", "", "the release tag (or its https URL) the host is rolling to")
	f.BoolVar(&dryRun, "dry-run", false, "stage and print the exact operations, without asking for an approval")
	f.BoolVar(&oneByOne, "one-by-one", false, "one approval per key")
	f.StringArrayVar(&exclude, "exclude", nil, "leave this app out, by name or id (repeatable)")
	f.IntVar(&parallel, "parallel", 4, "how many stages or promotes run at once")
	return cmd
}

// resolveEnclave finds an enclave by id or by name.
func resolveEnclave(ctx context.Context, client *api.Client, ref string) (map[string]interface{}, error) {
	if isUUID(ref) {
		return client.GetEnclave(ctx, ref)
	}
	enclaves, err := client.ListEnclaves(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range enclaves {
		if output.Str(e, "name") == ref {
			return e, nil
		}
	}
	return nil, fmt.Errorf("no enclave named %q on this platform", ref)
}

// releaseLabel is the description on the approval card, at most 120 characters.
func releaseLabel(release, enclave string) string {
	label := "Runtime " + path.Base(release) + " on " + enclave
	if r := []rune(label); len(r) > 120 {
		label = string(r[:120])
	}
	return strings.TrimSpace(label)
}

// releaseTargets lists what a roll of this enclave must promote: its manager
// key first, then each app with a vault-backed key.
func releaseTargets(ctx context.Context, client *api.Client, enclaveID, enclaveName, release string, exclude []string, out io.Writer) ([]approvalTarget, error) {
	placed, err := client.ListEnclaveApps(ctx, enclaveID)
	if err != nil {
		return nil, err
	}
	targets := []approvalTarget{{
		Name: "manager /data key",
		Prepare: func(ctx context.Context) ([]*approvalOp, error) {
			return prepareManagerKey(ctx, client, enclaveID, enclaveName, release)
		},
	}}
	excluded := map[string]bool{}
	for _, ref := range exclude {
		excluded[ref] = false
	}
	seen := map[string]bool{}
	for _, d := range placed {
		appID, name := output.Str(d, "app_id"), output.Str(d, "name")
		if seen[appID] {
			continue // the newest deployment of each app comes first
		}
		seen[appID] = true
		_, byName := excluded[name]
		_, byID := excluded[appID]
		if byName || byID {
			if byName {
				excluded[name] = true
			}
			if byID {
				excluded[appID] = true
			}
			fmt.Fprintf(out, "Left out: %s (--exclude). Its key will not admit the release.\n", name)
			continue
		}
		if t := output.Str(d, "app_type"); t != "" && t != "container" {
			continue // a WASM app's measurement does not follow the TDX runtime
		}
		deploymentID := output.Str(d, "deployment_id")
		targets = append(targets, approvalTarget{
			Name: name,
			Prepare: func(ctx context.Context) ([]*approvalOp, error) {
				return prepareAppKeys(ctx, client, appID, deploymentID, enclaveID, release)
			},
		})
	}
	for ref, used := range excluded {
		if !used {
			return nil, fmt.Errorf("--exclude %s: no such app on this enclave", ref)
		}
	}
	return targets, nil
}

func prepareManagerKey(ctx context.Context, client *api.Client, enclaveID, enclaveName, release string) ([]*approvalOp, error) {
	staged, err := client.StageDataKey(ctx, enclaveID, release)
	if err != nil {
		return nil, fmt.Errorf("stage: %w", err)
	}
	handle := output.Str(staged, "handle")
	if handle == "" {
		return nil, fmt.Errorf("stage: the platform named no key")
	}
	pendingID, policyVersion, err := agreedStage(staged["vaults"], "Success", "PendingID", "PolicyVersion", vaultQuorum)
	if err != nil {
		return nil, err
	}
	pending, err := client.DataKeyPending(ctx, enclaveID)
	if err != nil {
		return nil, fmt.Errorf("read the staged profile: %w", err)
	}
	digest, err := pendingDigest(pending["vaults"], "Pending", pendingID)
	if err != nil {
		return nil, err
	}
	return []*approvalOp{{
		BatchEntry: secrets.BatchEntry{
			Operation: "promote", Handle: handle, MeasurementDigest: digest, PolicyVersion: policyVersion,
			Context: map[string]string{"app_name": "Enclave manager: " + enclaveName, "version": path.Base(release), "key_type": "manager data key"},
		},
		Name: enclaveName,
		Kind: "manager /data key",
		Apply: func(ctx context.Context, token string) (string, error) {
			res, err := client.PromoteDataKey(ctx, enclaveID, pendingID, token)
			if err != nil {
				return "", err
			}
			return quorumNote(countSuccesses(res["vaults"], "Success"))
		},
	}}, nil
}

// prepareAppKeys stages an app for the release and returns the promote of its
// key and, for a private image, of its registry credential.
func prepareAppKeys(ctx context.Context, client *api.Client, appID, deploymentID, enclaveID, release string) ([]*approvalOp, error) {
	app, err := client.GetApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	handle := output.Str(app, "vault_key_handle")
	if handle == "" {
		return nil, nil // no vault-backed key: nothing to promote
	}
	versionID, err := deployedVersion(ctx, client, appID, deploymentID)
	if err != nil {
		return nil, err
	}
	staged, err := client.StageProfileForRelease(ctx, appID, versionID, enclaveID, release)
	if err != nil {
		return nil, fmt.Errorf("stage: %w", err)
	}
	if msg := output.Str(staged, "registry_cred_error"); msg != "" {
		return nil, fmt.Errorf("stage the registry credential: %s", msg)
	}
	pendingID, _, err := agreedStage(staged["vaults"], "ok", "pending_id", "policy_version", vaultQuorum)
	if err != nil {
		return nil, err
	}
	digest, policyVersion, err := pendingStepUpBinding(ctx, client, appID, versionID, int(pendingID))
	if err != nil {
		return nil, err
	}
	name := output.Str(app, "display_name")
	if name == "" {
		name = output.Str(app, "name")
	}
	display := promoteApprovalContext(ctx, client, appID, versionID)
	keyContext := withKeyType(display, "app key")
	ops := []*approvalOp{{
		BatchEntry: secrets.BatchEntry{
			Operation: "promote", Handle: handle, MeasurementDigest: digest, PolicyVersion: uint64(policyVersion), Context: keyContext,
		},
		Name: name,
		Kind: "app key",
		Apply: func(ctx context.Context, token string) (string, error) {
			sc := *client
			sc.Token = token
			res, err := sc.PromoteProfile(ctx, appID, versionID, int(pendingID))
			if err != nil {
				return "", err
			}
			return quorumNote(int(jsonNum(res["promoted"])))
		},
	}}

	cred, ok := staged["registry_cred"].(map[string]interface{})
	if !ok {
		return ops, nil
	}
	credHandle := output.Str(app, "registry_secret_handle")
	if credHandle == "" {
		credHandle = "apps.privasys.org/" + strings.ReplaceAll(appID, "-", "") + "/registry-cred/default"
	}
	credPending, credVersion, err := agreedStage(cred["vaults"], "ok", "pending_id", "policy_version", vaultQuorum)
	if err != nil {
		return nil, fmt.Errorf("registry credential: %w", err)
	}
	listed, err := client.ListPending(ctx, appID, versionID)
	if err != nil {
		return nil, fmt.Errorf("read the staged credential: %w", err)
	}
	listedCred, _ := listed["registry_cred"].(map[string]interface{})
	credDigest, err := pendingDigest(listedCred["vaults"], "pending", credPending)
	if err != nil {
		return nil, fmt.Errorf("registry credential: %w", err)
	}
	return append(ops, &approvalOp{
		BatchEntry: secrets.BatchEntry{
			Operation: "promote", Handle: credHandle, MeasurementDigest: credDigest, PolicyVersion: credVersion,
			Context: withKeyType(display, "registry credential"),
		},
		Name: name,
		Kind: "registry credential",
		Apply: func(ctx context.Context, token string) (string, error) {
			sc := *client
			sc.Token = token
			res, err := sc.PromoteRegistryCred(ctx, appID, versionID, credPending)
			if err != nil {
				return "", err
			}
			promoted, _ := res["registry_cred"].(map[string]interface{})
			return quorumNote(int(jsonNum(promoted["promoted"])))
		},
	}), nil
}

func withKeyType(base map[string]string, keyType string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out["key_type"] = keyType
	return out
}

// deployedVersion finds the version a placed deployment runs, so a stage never
// falls back on a default version.
func deployedVersion(ctx context.Context, client *api.Client, appID, deploymentID string) (string, error) {
	deployments, err := client.ListDeployments(ctx, appID)
	if err != nil {
		return "", err
	}
	for _, d := range deployments {
		if output.Str(d, "id") == deploymentID {
			if v := output.Str(d, "version_id"); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("deployment %s names no version", deploymentID)
}

// agreedStage reads the pending id and policy version a quorum of vaults
// reported for a stage. The platform omits a zero, and pending id 0 is real.
func agreedStage(vaults interface{}, okKey, pendingKey, versionKey string, quorum int) (uint32, uint64, error) {
	type stage struct {
		pending uint32
		version uint64
	}
	list, _ := vaults.([]interface{})
	counts := map[stage]int{}
	for _, v := range list {
		m, _ := v.(map[string]interface{})
		if m[okKey] != true {
			continue
		}
		counts[stage{uint32(jsonNum(m[pendingKey])), uint64(jsonNum(m[versionKey]))}]++
	}
	var agreed []stage
	for s, n := range counts {
		if n >= quorum {
			agreed = append(agreed, s)
		}
	}
	if len(agreed) != 1 {
		return 0, 0, fmt.Errorf("no %d vaults agree on what was staged (%d answered)", quorum, len(list))
	}
	return agreed[0].pending, agreed[0].version, nil
}

// pendingDigest computes the binding digest of a staged profile as the vault
// will. Every vault holding this pending id must hold the same profile.
func pendingDigest(vaults interface{}, pendingKey string, pendingID uint32) (string, error) {
	list, _ := vaults.([]interface{})
	digest := ""
	for _, v := range list {
		m, _ := v.(map[string]interface{})
		pending, _ := m[pendingKey].([]interface{})
		for _, p := range pending {
			pm, _ := p.(map[string]interface{})
			if uint32(jsonNum(pm["id"])) != pendingID {
				continue
			}
			profile, _ := pm["profile"].(map[string]interface{})
			d := profileBindingDigest(profile)
			if digest != "" && d != digest {
				return "", fmt.Errorf("the vaults hold different profiles under pending #%d", pendingID)
			}
			digest = d
		}
	}
	if digest == "" {
		return "", fmt.Errorf("pending profile #%d was not found on any vault", pendingID)
	}
	return digest, nil
}

// profileBindingDigest must stay byte-identical to the vault's: each
// measurement and required OID as a kind:value line, values lowercased (the OID
// key is not), the lines sorted and newline-joined, then SHA-256 in hex.
func profileBindingDigest(profile map[string]interface{}) string {
	var parts []string
	measurements, _ := profile["measurements"].([]interface{})
	for _, m := range measurements {
		mm, _ := m.(map[string]interface{})
		if tdx, ok := mm["Tdx"].(map[string]interface{}); ok {
			parts = append(parts, "mrtd:"+strings.ToLower(output.Str(tdx, "mrtd")),
				"rtmr1:"+strings.ToLower(output.Str(tdx, "rtmr1")),
				"rtmr2:"+strings.ToLower(output.Str(tdx, "rtmr2")))
		} else if me := output.Str(mm, "Mrenclave"); me != "" {
			parts = append(parts, "mrenclave:"+strings.ToLower(me))
		}
	}
	oids, _ := profile["required_oids"].([]interface{})
	for _, o := range oids {
		om, _ := o.(map[string]interface{})
		parts = append(parts, "oid:"+output.Str(om, "oid")+"="+strings.ToLower(output.Str(om, "value")))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func countSuccesses(vaults interface{}, okKey string) int {
	list, _ := vaults.([]interface{})
	n := 0
	for _, v := range list {
		if m, _ := v.(map[string]interface{}); m[okKey] == true {
			n++
		}
	}
	return n
}

// quorumNote turns a vault count into the outcome of a promote.
func quorumNote(promoted int) (string, error) {
	if promoted < vaultQuorum {
		return "", fmt.Errorf("promoted on %d vaults, %d needed", promoted, vaultQuorum)
	}
	return fmt.Sprintf("promoted on %d vaults", promoted), nil
}
