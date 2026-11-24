// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

// newVaultIdentityCmd reads the member identities of a vault constellation,
// each over its own RA-TLS connection pinned to the constellation's MRENCLAVE:
// the member ids an approval on binding v2 names.
func newVaultIdentityCmd() *cobra.Command {
	var constellation string
	cmd := &cobra.Command{
		Use:    "identity",
		Short:  "Show the member vaults of a constellation, read from the vaults themselves",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			dir, err := client.VaultDirectoryAt(cmd.Context(), constellation)
			if err != nil {
				return err
			}
			attTok, _ := auth.AccessTokenForAudience(cmd.Context(), env.Cfg.Issuer, "attestation-server")
			ids, err := secrets.ConstellationIdentities(cmd.Context(), dir.Endpoints, dir.MRENCLAVE, dir.AttestationServer, attTok)
			if err != nil {
				return err
			}
			type member struct {
				Endpoint  string `json:"endpoint"`
				MemberID  string `json:"member_id"`
				BillingID string `json:"billing_id"`
			}
			members := make([]member, len(ids))
			for i, id := range ids {
				members[i] = member{Endpoint: dir.Endpoints[i], MemberID: id.MemberID(), BillingID: id.BillingID()}
			}
			out := map[string]any{"constellation": dir.ID, "name": dir.Name, "mrenclave": dir.MRENCLAVE, "members": members}
			return output.Emit(env.Format, out, func() output.Table {
				rows := [][]string{}
				for _, m := range members {
					rows = append(rows, []string{m.Endpoint, m.MemberID, m.BillingID})
				}
				return output.Table{Headers: []string{"VAULT", "MEMBER ID", "BILLING ID"}, Rows: rows}
			})
		},
	}
	cmd.Flags().StringVar(&constellation, "constellation", "", "constellation id (default: the active one)")
	return cmd
}
