// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Privasys/enclave-vaults-client/go/vault"
	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

// checkDeleteApproval checks the control plane's delete_approval against the
// rotation or migration it answers and the app it is for: a delete_after of
// that answer's old key, replaced by that answer's new key, both the app's.
func checkDeleteApproval(appID string, res map[string]interface{}, da *api.DeleteApproval) error {
	if da.Operation != string(vault.BindDeleteAfter) || da.BindingVersion != 2 {
		return fmt.Errorf("the control plane asks for %s (binding %d), not a delete_after", da.Operation, da.BindingVersion)
	}
	prefix := "apps.privasys.org/" + strings.ReplaceAll(appID, "-", "") + "/"
	if !strings.HasPrefix(da.Handle, prefix) || !strings.HasPrefix(da.SuccessorHandle, prefix) {
		return errors.New("the keys named are not this app's")
	}
	if da.Handle == da.SuccessorHandle {
		return errors.New("a key cannot be its own successor")
	}
	if old := output.Str(res, "old_handle"); old != "" && old != da.Handle {
		return fmt.Errorf("the delete names %s, the rotation replaced %s", da.Handle, old)
	}
	if next := output.Str(res, "new_handle"); next == "" || next != da.SuccessorHandle {
		return fmt.Errorf("the delete names successor %s, the rotation made %s", da.SuccessorHandle, next)
	}
	return nil
}

// deleteOldKey finishes a rotation or migration on binding-v2 vaults: when the
// answer carries a delete_approval, it checks it, asks the owner to approve
// deleting the old key now that its successor exists, and has the control
// plane delete it. A decline, or a failure, leaves the old key to expire on
// its own; res says which.
func deleteOldKey(cmd *cobra.Command, env *Env, client *api.Client, appID string, res map[string]interface{}) {
	da, ok := api.DeleteApprovalFrom(res)
	if !ok {
		return
	}
	note := func(key, msg string) {
		res[key] = msg
		if !env.Quiet {
			fmt.Fprintln(cmd.ErrOrStderr(), msg)
		}
	}
	if err := approveAndDeleteOldKey(cmd, env, client, appID, res, da); err != nil {
		note("warning", "the previous key was not deleted ("+err.Error()+"); it stops being served when it expires")
		return
	}
	res["old_key_deleted"] = true
	delete(res, "delete_approval")
	if !env.Quiet {
		output.Success(cmd.ErrOrStderr(), "Deleted the previous key %s", da.Handle)
	}
}

func approveAndDeleteOldKey(cmd *cobra.Command, env *Env, client *api.Client, appID string, res map[string]interface{}, da *api.DeleteApproval) error {
	ctx := cmd.Context()
	if err := checkDeleteApproval(appID, res, da); err != nil {
		return fmt.Errorf("refusing the delete: %w", err)
	}
	d, err := client.VaultDirectoryAt(ctx, da.ConstellationID)
	if err != nil {
		return fmt.Errorf("the old key's vaults: %w", err)
	}
	audience, err := vaultApprovalAudience(d.OIDCAudience)
	if err != nil {
		return err
	}
	if da.Audience != "" && da.Audience != audience {
		return fmt.Errorf("refusing the delete: the control plane asks for audience %q, the old key's vaults accept %q", da.Audience, audience)
	}
	vaultTok, err := auth.VaultTokenFor(ctx, env.Cfg.Issuer, audience)
	if err != nil {
		return err
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	// The identities and version come from the old key's vaults, never from
	// the control plane's bundle.
	binding, ids, policyVersion, err := secrets.KeyApproval(ctx, secrets.KeyTarget{Handle: da.Handle, Endpoints: d.Endpoints,
		MRENCLAVE: d.MRENCLAVE, AttServer: d.AttestationServer, AttToken: attTok, Bearer: vaultTok}, vault.OpDeleteKey)
	if err != nil {
		return err
	}
	if binding != 2 {
		return fmt.Errorf("refusing the delete: the old key's vaults take binding %d", binding)
	}
	if uint64(policyVersion) != da.PolicyVersion {
		return fmt.Errorf("refusing the delete: the old key's vaults hold policy version %d, the delete is for %d", policyVersion, da.PolicyVersion)
	}
	read := make([]string, len(ids))
	for i, id := range ids {
		read[i] = id.MemberID()
	}
	sent := append([]string(nil), da.Members...)
	sort.Strings(read)
	sort.Strings(sent)
	if strings.Join(read, ",") != strings.Join(sent, ",") {
		return errors.New("refusing the delete: the control plane names other vaults than the old key's")
	}
	actx := map[string]string{"app_id": appID,
		"summary": "Delete the previous key now that " + da.SuccessorHandle + " replaces it"}
	if name := appFriendlyName(ctx, client, appID); name != "" {
		actx["app_name"] = name
	}
	if info, ierr := secrets.KeyInfoAt(ctx, d, vaultTok, attTok, da.Handle); ierr == nil && info.KeyType != "" {
		actx["key_type"] = string(info.KeyType)
	}
	approval, err := secrets.DeleteAfterSuccessorApproval(da.Handle, da.SuccessorHandle, da.PolicyVersion, ids, audience, actx)
	if err != nil {
		return fmt.Errorf("refusing the delete: %w", err)
	}
	bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return err
	}
	if !env.Quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nApprove deleting the previous key %s.\n", da.Handle)
	}
	tok, err := secrets.RequestApprovalV2(ctx, env.Cfg.Issuer, bearer, approval, secrets.OpenBrowser, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	sc := *client
	sc.Token = tok
	out, err := sc.DeleteOldKey(ctx, appID, da)
	if err != nil {
		return err
	}
	res["old_key_delete"] = out
	return nil
}
