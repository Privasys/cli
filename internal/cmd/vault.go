// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

func newVaultCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "vault",
		Short: "Create and manage your vaults (key containers) and the keys in them",
		Long: `A vault is a container of keys that you own, backed by the Shamir-split vault
constellation so no single vault holds a key and the platform never sees the
material. Each vault is billed to your account; the number of vaults you may
create is set by your plan.`,
	}
	c.AddCommand(newVaultCreateCmd(), newVaultListCmd(), newVaultRmCmd(), newVaultKeyCmd())
	return c
}

func newVaultCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			v, err := client.CreateVault(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Created vault %v", v["name"])
			}
			return output.Emit(env.Format, v, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"id", fmt.Sprintf("%v", v["id"])},
					{"name", fmt.Sprintf("%v", v["name"])},
					{"kind", fmt.Sprintf("%v", v["kind"])},
				}}
			})
		},
	}
	return cmd
}

func newVaultListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your vaults",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			vaults, err := client.ListVaults(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, vaults, func() output.Table {
				rows := make([][]string, 0, len(vaults))
				for _, v := range vaults {
					rows = append(rows, []string{
						fmt.Sprintf("%v", v["id"]), fmt.Sprintf("%v", v["name"]), fmt.Sprintf("%v", v["kind"]),
					})
				}
				return output.Table{Headers: []string{"ID", "NAME", "KIND"}, Rows: rows}
			})
		},
	}
	return cmd
}

func newVaultRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <vault-id>",
		Short: "Delete a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			if err := client.DeleteVault(cmd.Context(), args[0]); err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Deleted vault %s", args[0])
			}
			return output.Emit(env.Format, map[string]any{"deleted": true}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{{"deleted", "true"}}}
			})
		},
	}
	return cmd
}

func newVaultKeyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "Create, list and remove keys in a vault",
	}
	c.AddCommand(newVaultKeyCreateCmd(), newVaultKeyListCmd(), newVaultKeyRmCmd())
	return c
}

func newVaultKeyCreateCmd() *cobra.Command {
	var value, fromFile string
	var randomBytes int
	var exportable bool
	cmd := &cobra.Command{
		Use:   "create <vault-id> <name>",
		Short: "Create a Shamir-split key in a vault",
		Long: `Creates a key in a vault. You authenticate; the platform verifies you may use
the vault, authors the key's owner-bound policy and mints a short-lived,
holder-of-key-bound grant; the CLI then creates the material directly on the
constellation. The platform never sees the key material.

Provide the material with --value or --from-file, or omit both to generate
--random-bytes of randomness.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			tok, err := auth.AccessToken(ctx, env.Cfg.Issuer)
			if err != nil {
				return err
			}
			claims, err := auth.Claims(tok)
			if err != nil {
				return err
			}
			sub, _ := claims["sub"].(string)
			if sub == "" {
				return fmt.Errorf("could not determine your subject from the session")
			}
			secret, err := resolveSecretMaterial(value, fromFile, randomBytes)
			if err != nil {
				return err
			}
			// Used only to verify the vaults' own quotes during the RA-TLS dial.
			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}

			vaultID, name := args[0], args[1]
			res, err := secrets.CreateInVault(ctx, secrets.VaultCreateParams{
				Sub: sub, Secret: secret, Exportable: exportable, AttToken: attTok,
				MintGrant: func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
					return mintVaultKeyGrant(ctx, client, vaultID, name, cnf, exportable)
				},
			})
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Created key %s (%d/%d vaults, threshold %d)",
					res.Handle, res.Created, res.Total, res.Threshold)
			}
			return output.Emit(env.Format, res, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", res.Handle},
					{"vaults", fmt.Sprintf("%d/%d (threshold %d)", res.Created, res.Total, res.Threshold)},
					{"exportable", fmt.Sprintf("%t", res.Exportable)},
				}}
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&value, "value", "", "key value (a string)")
	f.StringVar(&fromFile, "from-file", "", "read the key bytes from a file")
	f.IntVar(&randomBytes, "random-bytes", 32, "generate this many random bytes when no value/file is given")
	f.BoolVar(&exportable, "exportable", true, "allow the owner to export the key later")
	return cmd
}

// mintVaultKeyGrant asks the platform to mint the grant for a new key and maps
// the response into the addressing the agent needs.
func mintVaultKeyGrant(ctx context.Context, client *api.Client, vaultID, name, cnf string, exportable bool) (string, secrets.VaultAddressing, error) {
	r, err := client.MintVaultKeyGrant(ctx, vaultID, name, "", cnf, exportable)
	if err != nil {
		return "", secrets.VaultAddressing{}, err
	}
	handle, _ := r.Key["handle"].(string)
	return r.Grant, secrets.VaultAddressing{
		Handle:    handle,
		Endpoints: r.Constellation.Endpoints,
		MRENCLAVE: r.Constellation.MRENCLAVE,
		AttServer: r.Constellation.AttestationServer,
		Threshold: r.Constellation.Threshold,
	}, nil
}

func newVaultKeyListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <vault-id>",
		Short: "List the keys in a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			keys, err := client.ListVaultKeys(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, keys, func() output.Table {
				rows := make([][]string, 0, len(keys))
				for _, k := range keys {
					rows = append(rows, []string{
						fmt.Sprintf("%v", k["name"]), fmt.Sprintf("%v", k["key_type"]),
						fmt.Sprintf("%v", k["kind"]), fmt.Sprintf("%v", k["exportable"]),
					})
				}
				return output.Table{Headers: []string{"NAME", "TYPE", "KIND", "EXPORTABLE"}, Rows: rows}
			})
		},
	}
	return cmd
}

func newVaultKeyRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <vault-id> <name>",
		Short: "Remove a key's catalogue entry from a vault",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			if err := client.DeleteVaultKey(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Removed key %s from vault %s", args[1], args[0])
			}
			return output.Emit(env.Format, map[string]any{"deleted": true}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{{"deleted", "true"}}}
			})
		},
	}
	return cmd
}
