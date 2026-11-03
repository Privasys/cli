// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Privasys/cli/internal/output"
	"github.com/spf13/cobra"
)

func newOAuthClientsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "oauth-clients",
		Aliases: []string{"oauth-client"},
		Short:   "Manage the sign-in clients your account owns",
	}
	c.AddCommand(newFederationCmd())
	return c
}

func newFederationCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "federation",
		Short: "Sign a client's users in through your own identity provider registration",
		Long: `A sign-in client can use your own registration with an identity provider
(a Microsoft Entra app registration) instead of the platform's. Your users stay
the same accounts: they are identified by their directory object id, whichever
registration signed them in.

The preferred credential is a certificate: the platform generates the key, keeps
it, never shares it, and prints the public certificate for you to upload. Run
'set' again before the certificate expires to rotate: the old key keeps working
until you run 'confirm-rotation'.`,
	}
	c.AddCommand(newFederationSetCmd(), newFederationConfirmCmd(), newFederationShowCmd(), newFederationRemoveCmd())
	return c
}

func newFederationSetCmd() *cobra.Command {
	var tenant, upstreamClient, displayName string
	var certificate, secretStdin bool
	cmd := &cobra.Command{
		Use:   "set <client-id> <provider>",
		Short: "Register or rotate a client's own registration (provider: microsoft)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if certificate == secretStdin {
				return errors.New("choose one credential: --certificate or --client-secret-stdin")
			}
			credential := map[string]interface{}{"kind": "certificate"}
			if secretStdin {
				// Never on a command line, where it would reach shell history.
				raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 8<<10))
				if err != nil {
					return err
				}
				secret := strings.TrimSpace(string(raw))
				if secret == "" {
					return errors.New("no client secret on stdin")
				}
				credential = map[string]interface{}{"kind": "secret", "secret": secret}
			}
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.SetFederation(cmd.Context(), args[0], args[1], map[string]interface{}{
				"client_id": upstreamClient, "tenant": tenant, "display_name": displayName, "credential": credential,
			})
			if err != nil {
				return err
			}
			return emitFederation(cmd, env, res)
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant id or verified domain, or 'common' for a multi-tenant registration")
	cmd.Flags().StringVar(&upstreamClient, "client-id", "", "The registration's application (client) id")
	cmd.Flags().StringVar(&displayName, "display-name", "", "The name on the sign-in button, e.g. your organisation")
	cmd.Flags().BoolVar(&certificate, "certificate", false, "Generate a certificate credential and print it for upload (preferred)")
	cmd.Flags().BoolVar(&secretStdin, "client-secret-stdin", false, "Read a client secret from stdin")
	_ = cmd.MarkFlagRequired("tenant")
	_ = cmd.MarkFlagRequired("client-id")
	return cmd
}

func emitFederation(cmd *cobra.Command, env *Env, res map[string]interface{}) error {
	if env.Format == "json" {
		return output.Emit(env.Format, res, nil)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s: %s in tenant %s, credential %s\n", output.Str(res, "provider"), output.Str(res, "client_id"), output.Str(res, "tenant"), output.Str(res, "credential_kind"))
	if exp := output.Str(res, "expires_at"); exp != "" {
		fmt.Fprintf(out, "Certificate expires %s\n", exp)
	}
	if pem := output.Str(res, "certificate"); pem != "" {
		fmt.Fprintf(out, "\nUpload this certificate to the app registration (Certificates & secrets):\n\n%s\n", pem)
	}
	if res["rotation_pending"] == true {
		fmt.Fprintln(out, "The old key keeps signing. After uploading, run: privasys oauth-clients federation confirm-rotation <client-id> <provider>")
	}
	return nil
}

func newFederationConfirmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "confirm-rotation <client-id> <provider>",
		Short: "Say the rotated certificate is uploaded: it starts signing and the old key is destroyed",
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
			res, err := client.ConfirmFederationRotation(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				return kvTable(res, []string{"provider", "client_id", "tenant", "credential_kind", "expires_at"})
			})
		},
	}
}

func newFederationShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <client-id>",
		Short: "List a client's own registrations and when their certificates expire",
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
			res, err := client.GetFederation(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				t := output.Table{Headers: []string{"PROVIDER", "CLIENT ID", "TENANT", "NAME", "CREDENTIAL", "EXPIRES", "ROTATION PENDING"}}
				entries, _ := res["federation"].([]interface{})
				for _, raw := range entries {
					e, _ := raw.(map[string]interface{})
					t.Rows = append(t.Rows, []string{
						output.Str(e, "provider"), output.Str(e, "client_id"), output.Str(e, "tenant"), output.Str(e, "display_name"),
						output.Str(e, "credential_kind"), output.Str(e, "expires_at"), fmt.Sprint(e["rotation_pending"] == true),
					})
				}
				return t
			})
		},
	}
}

func newFederationRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <client-id> <provider>",
		Short: "Return a client's users to the platform's registration",
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
			if err := client.RemoveFederation(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed: users of %s sign in with %s through the platform's registration\n", args[0], args[1])
			return nil
		},
	}
}
