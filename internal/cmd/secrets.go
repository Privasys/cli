// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

func newSecretsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "secrets",
		Short: "Create and export user-owned secrets in the vault constellation",
	}
	c.AddCommand(newSecretsCreateCmd())
	c.AddCommand(newSecretsExportCmd())
	return c
}

// walletStepUpApprover returns the WebAuthn step-up assertion for an export.
// Export requires a fresh, operation-bound WebAuthn assertion from the owner's
// wallet/passkey. CLI-driven wallet approval (the Privasys Wallet "Vault
// approvals" relay) is still rolling out, so for now this surfaces a clear
// instruction. The export MECHANISM is complete end to end (the E2E suite drives
// it with a software authenticator); only this human hand-off is pending.
func walletStepUpApprover() secrets.StepUpAssertFunc {
	return func(_ context.Context, _ []byte) ([]byte, error) {
		return nil, fmt.Errorf("this export needs WebAuthn step-up: approve it in the Privasys Wallet " +
			"under Vault approvals. CLI-driven wallet approval is rolling out; until then complete the " +
			"export from a device holding your passkey")
	}
}

func newSecretsCreateCmd() *cobra.Command {
	var value, fromFile string
	var randomBytes, threshold int
	var exportable bool
	var endpoints []string
	var mrenclave, attServer string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a user-owned, Shamir-split secret in the vault",
		Long: `Creates a secret (key) that YOU own, split across the vault constellation so
no single vault holds it and the platform never sees it. You authenticate; the
CLI obtains a short-lived key-creation grant from the IdP (holder-of-key bound
to an ephemeral RA-TLS cert) and creates the key directly on the vaults.

Provide the material with --value or --from-file, or omit both to generate
--random-bytes of randomness. An exportable secret can later be retrieved by
you (the owner); the material is never printed.`,
		Args: cobra.ExactArgs(1),
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

			if len(endpoints) == 0 {
				endpoints = secrets.DefaultEndpoints
			}
			if mrenclave == "" {
				mrenclave = secrets.DefaultMRENCLAVE
			}
			if attServer == "" {
				attServer = secrets.DefaultAttServer
			}

			handle := "users/" + sub + "/" + args[0]
			res, err := secrets.Create(ctx, secrets.CreateParams{
				Issuer: env.Cfg.Issuer, Bearer: tok, Sub: sub, Handle: handle,
				Secret: secret, Exportable: exportable, Endpoints: endpoints,
				Threshold: threshold, MRENCLAVE: mrenclave, AttServer: attServer, AttToken: attTok,
			})
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Created secret %s (%d/%d vaults, threshold %d)",
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
	f.StringVar(&value, "value", "", "secret value (a string)")
	f.StringVar(&fromFile, "from-file", "", "read the secret bytes from a file")
	f.IntVar(&randomBytes, "random-bytes", 32, "generate this many random bytes when no value/file is given")
	f.BoolVar(&exportable, "exportable", true, "allow the owner to export the secret later")
	f.IntVar(&threshold, "threshold", 2, "Shamir threshold (k of n vaults)")
	f.StringArrayVar(&endpoints, "vault", nil, "vault endpoint host:port (repeatable; default: the production constellation)")
	f.StringVar(&mrenclave, "mrenclave", "", "expected vault MRENCLAVE (hex; default: production)")
	f.StringVar(&attServer, "attestation-server", "", "attestation server verify URL")
	return cmd
}

func newSecretsExportCmd() *cobra.Command {
	var out string
	var threshold int
	var endpoints []string
	var mrenclave, attServer string
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Export a secret you own to a local file (DANGEROUS)",
		Long: `Retrieves a secret YOU own from the vault constellation and writes the raw key
to a local file. The vaults each return only their share; the key is
reconstructed on your machine.

DANGER: this writes raw key material to disk. The material is never printed and
never leaves your machine through this CLI. Export requires a fresh WebAuthn
step-up from your wallet/passkey (a leaked session alone cannot export).

The file is written with 0600 permissions; the command prints only the path and
a fingerprint, never the key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return fmt.Errorf("--out <file> is required (the key is written to a local file only)")
			}
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
			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")

			if len(endpoints) == 0 {
				endpoints = secrets.DefaultEndpoints
			}
			if mrenclave == "" {
				mrenclave = secrets.DefaultMRENCLAVE
			}
			if attServer == "" {
				attServer = secrets.DefaultAttServer
			}

			handle := "users/" + sub + "/" + args[0]
			material, res, err := secrets.Export(ctx, secrets.ExportParams{
				Issuer: env.Cfg.Issuer, Bearer: tok, Sub: sub, Handle: handle,
				Endpoints: endpoints, Threshold: threshold, MRENCLAVE: mrenclave,
				AttServer: attServer, AttToken: attTok,
				RequireStepUp: true, Assert: walletStepUpApprover(),
			})
			if err != nil {
				return err
			}
			// Write the key to the local file only; then wipe it from memory.
			werr := os.WriteFile(out, material, 0o600)
			for i := range material {
				material[i] = 0
			}
			if werr != nil {
				return fmt.Errorf("write %s: %w", out, werr)
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Wrote %s (%d/%d vaults, %s)",
					out, res.Retrieved, res.Total, res.Fingerprint)
			}
			return output.Emit(env.Format, map[string]interface{}{
				"handle": res.Handle, "path": out, "fingerprint": res.Fingerprint,
				"vaults": res.Retrieved, "written": true,
			}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", res.Handle},
					{"path", out},
					{"fingerprint", res.Fingerprint},
				}}
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "", "write the raw key to this local file (required)")
	f.IntVar(&threshold, "threshold", 2, "Shamir threshold (k of n vaults)")
	f.StringArrayVar(&endpoints, "vault", nil, "vault endpoint host:port (repeatable; default: the production constellation)")
	f.StringVar(&mrenclave, "mrenclave", "", "expected vault MRENCLAVE (hex; default: production)")
	f.StringVar(&attServer, "attestation-server", "", "attestation server verify URL")
	return cmd
}

// resolveSecretMaterial picks the secret bytes from exactly one source.
func resolveSecretMaterial(value, fromFile string, randomBytes int) ([]byte, error) {
	switch {
	case value != "" && fromFile != "":
		return nil, fmt.Errorf("pass only one of --value or --from-file")
	case value != "":
		return []byte(value), nil
	case fromFile != "":
		return os.ReadFile(fromFile)
	default:
		if randomBytes <= 0 || randomBytes > 4096 {
			return nil, fmt.Errorf("--random-bytes must be between 1 and 4096")
		}
		b := make([]byte, randomBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	}
}
