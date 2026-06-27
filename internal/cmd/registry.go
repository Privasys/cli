// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

func newRegistryCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "registry",
		Short: "Manage private-image pull credentials for your apps",
		Long: `Register a private registry's pull credential so Privasys can run your own
image confidentially without the platform, the host, or anyone else seeing the
image bytes or the token. The credential is stored in the vault constellation;
only the attested in-TEE manager can export it, and only to pull your app's
image. The token goes straight into the vault — it is never printed or stored
by the control plane.`,
	}
	c.AddCommand(newRegistryAddCmd(), newRegistryStatusCmd(), newRegistryRmCmd())
	return c
}

func newRegistryAddCmd() *cobra.Command {
	var token, username, password, enclave string
	cmd := &cobra.Command{
		Use:   "add <app> [name]",
		Short: "Register a private-registry pull credential for an app",
		Long: `Stores a registry pull credential in the vault for <app>'s private image.
Provide either --token (a single pull token / PAT) or --username + --password.
The optional [name] lets an app carry more than one credential (default
"default").`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			cred, err := buildRegistryCredential(token, username, password)
			if err != nil {
				return err
			}
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
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			name := ""
			if len(args) == 2 {
				name = args[1]
			}
			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")

			res, err := secrets.CreateInVault(ctx, secrets.VaultCreateParams{
				Sub: sub, Secret: cred, Exportable: true, AttToken: attTok,
				MintGrant: func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
					r, err := client.AddRegistrySecret(ctx, appID, name, cnf, enclave)
					if err != nil {
						return "", secrets.VaultAddressing{}, err
					}
					return r.Grant, secrets.VaultAddressing{
						Handle:    r.Handle,
						Endpoints: r.Constellation.Endpoints,
						MRENCLAVE: r.Constellation.MRENCLAVE,
						AttServer: r.Constellation.AttestationServer,
						Threshold: r.Constellation.Threshold,
					}, nil
				},
			})
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Registered pull credential %s (%d/%d vaults, threshold %d)",
					res.Handle, res.Created, res.Total, res.Threshold)
			}
			return output.Emit(env.Format, res, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", res.Handle},
					{"vaults", fmt.Sprintf("%d/%d (threshold %d)", res.Created, res.Total, res.Threshold)},
				}}
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&token, "token", "", "a single pull token / PAT (used as the password)")
	f.StringVar(&username, "username", "", "registry username (with --password)")
	f.StringVar(&password, "password", "", "registry password (with --username)")
	f.StringVar(&enclave, "enclave", "", "target enclave id (defaults to the app's assigned enclave)")
	return cmd
}

// buildRegistryCredential turns the flags into the {username,password} JSON the
// in-TEE manager expects. --token is shorthand for a tokens-as-password registry
// (any username is accepted); --username/--password is the explicit form.
func buildRegistryCredential(token, username, password string) ([]byte, error) {
	switch {
	case password != "":
		if username == "" {
			username = "x-access-token"
		}
	case token != "":
		password = token
		if username == "" {
			username = "x-access-token"
		}
	default:
		return nil, fmt.Errorf("provide --token, or --username and --password")
	}
	return json.Marshal(map[string]string{"username": username, "password": password})
}

func newRegistryStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <app>",
		Short: "Show whether an app has a pull credential configured",
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
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			m, err := client.GetRegistrySecret(cmd.Context(), appID)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, m, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"configured", fmt.Sprintf("%v", m["set"])},
					{"handle", fmt.Sprintf("%v", m["handle"])},
				}}
			})
		},
	}
	return cmd
}

func newRegistryRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <app>",
		Short: "Clear an app's pull credential (it pulls anonymously again)",
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
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			if err := client.DeleteRegistrySecret(cmd.Context(), appID); err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Cleared pull credential for %s", args[0])
			}
			return output.Emit(env.Format, map[string]any{"cleared": true}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{{"cleared", "true"}}}
			})
		},
	}
	return cmd
}
