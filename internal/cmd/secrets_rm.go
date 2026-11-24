// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

func newSecretsRmCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a secret you own from the vaults (cannot be undone)",
		Long: `Finds a secret you own on the vault constellations and destroys its material
on every vault that holds it. This cannot be undone: export the secret first if
you may need its value again.

A secret whose policy asks for it is deleted only with your approval in the
Privasys Wallet. When the secret has several generations, the newest one is
deleted; older ones expire on their own.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := newSecretSession(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			home, info, err := secrets.LocateSecret(ctx, s.client, s.handle(args[0]), vaultTokens(s.env), s.attTok)
			if err != nil {
				return err
			}
			if info.Warning != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+info.Warning)
			}
			if !yes {
				ok, err := confirm(cmd, s.env, fmt.Sprintf("Destroy %s on %s? This cannot be undone. [y/N] ", info.Handle, home.Name))
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("nothing was deleted")
				}
			}
			ownerTok, err := auth.VaultTokenFor(ctx, s.env.Cfg.Issuer, home.OIDCAudience)
			if err != nil {
				return err
			}
			deletedOn, err := secrets.DestroyKeyInVault(ctx, secrets.VaultOpParams{
				Handle: info.Handle, Endpoints: home.Endpoints, MRENCLAVE: home.MRENCLAVE,
				AttServer: home.AttestationServer, AttToken: s.attTok, OwnerToken: ownerTok,
				ApproveV2: secretApprover(cmd, s, home.OIDCAudience, args[0]),
			})
			if err != nil {
				return err
			}
			if !s.env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Deleted %s (%d/%d vaults)", info.Handle, len(deletedOn), len(home.Endpoints))
			}
			return output.Emit(s.env.Format, map[string]any{
				"handle": info.Handle, "constellation": home.Name, "constellation_id": home.ID, "deleted_on": len(deletedOn),
			}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", info.Handle},
					{"constellation", home.Name},
					{"deleted on", fmt.Sprintf("%d of %d vaults", len(deletedOn), len(home.Endpoints))},
				}}
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "delete without an interactive confirmation")
	return cmd
}
