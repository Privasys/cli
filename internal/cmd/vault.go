// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

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
	c.AddCommand(newVaultKeyCreateCmd(), newVaultKeyListCmd(), newVaultKeyRmCmd(),
		newVaultKeySignCmd(), newVaultKeyPublicCmd(),
		newVaultKeyWrapCmd(), newVaultKeyUnwrapCmd())
	return c
}

func newVaultKeyCreateCmd() *cobra.Command {
	var value, fromFile, keyType string
	var randomBytes int
	var exportable bool
	cmd := &cobra.Command{
		Use:   "create <vault-id> <name>",
		Short: "Create a key in a vault (secret or signing key)",
		Long: `Creates a key in a vault. You authenticate; the platform verifies you may use
the vault, authors the key's owner-bound policy and mints a short-lived,
holder-of-key-bound grant; the CLI then creates the material directly on the
constellation. The platform never sees the key material.

--type secret (default): a Shamir-split secret across the constellation. Provide
  it with --value or --from-file, or omit both to generate --random-bytes.
--type p256: a managed ECDSA P-256 signing key — generated client-side, created
  whole on one vault, signed in-enclave (the private key never leaves), and
  non-exportable by default. Use 'vault key sign' / 'vault key public'.
--type aes: a managed AES-256-GCM wrapping key — 32 random bytes created whole on
  one vault; wrap/unwrap happen in-enclave (the key never leaves), non-exportable.
  Use 'vault key wrap' / 'vault key unwrap'.`,
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
			vaultKeyType, operational, err := resolveVaultKeyType(keyType)
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

			// An operational key (signing / wrapping) is whole + non-exportable
			// (in-enclave use only); a RawShare secret keeps the export default.
			exp := exportable
			if operational {
				exp = false
			}
			mint := func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
				return mintVaultKeyGrant(ctx, client, vaultID, name, vaultKeyType, cnf, exp)
			}

			var res *secrets.Result
			params := secrets.VaultCreateParams{Sub: sub, Exportable: exp, AttToken: attTok, MintGrant: mint}
			switch {
			case vaultKeyType == "P256SigningKey":
				res, err = secrets.CreateSigningKeyInVault(ctx, params)
			case vaultKeyType == "Aes256GcmKey":
				res, err = secrets.CreateAesKeyInVault(ctx, params)
			default:
				var secret []byte
				if secret, err = resolveSecretMaterial(value, fromFile, randomBytes); err == nil {
					params.Secret = secret
					res, err = secrets.CreateInVault(ctx, params)
				}
			}
			if err != nil {
				return err
			}
			if !env.Quiet {
				if operational {
					output.Success(cmd.ErrOrStderr(), "Created %s %s on %s", vaultKeyType, res.Handle, res.Endpoint)
				} else {
					output.Success(cmd.ErrOrStderr(), "Created key %s (%d/%d vaults, threshold %d)",
						res.Handle, res.Created, res.Total, res.Threshold)
				}
			}
			return output.Emit(env.Format, res, func() output.Table {
				rows := [][]string{{"handle", res.Handle}}
				if operational {
					rows = append(rows, []string{"type", vaultKeyType}, []string{"vault", res.Endpoint})
				} else {
					rows = append(rows, []string{"vaults", fmt.Sprintf("%d/%d (threshold %d)", res.Created, res.Total, res.Threshold)})
				}
				rows = append(rows, []string{"exportable", fmt.Sprintf("%t", res.Exportable)})
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&keyType, "type", "secret", "key type: secret | p256 (signing) | aes (wrapping)")
	f.StringVar(&value, "value", "", "secret value (a string); --type secret only")
	f.StringVar(&fromFile, "from-file", "", "read the secret bytes from a file; --type secret only")
	f.IntVar(&randomBytes, "random-bytes", 32, "generate this many random bytes when no value/file is given")
	f.BoolVar(&exportable, "exportable", true, "allow the owner to export a secret later (signing keys are never exportable by default)")
	return cmd
}

// resolveVaultKeyType maps the --type flag to the vault KeyType + whether it is
// an operational (whole-key, in-enclave, non-exportable) type vs a RawShare
// secret.
func resolveVaultKeyType(t string) (vaultKeyType string, operational bool, err error) {
	switch t {
	case "", "secret", "raw", "RawShare":
		return "", false, nil // "" => the platform defaults to RawShare
	case "p256", "P256", "P256SigningKey", "ecdsa-p256":
		return "P256SigningKey", true, nil
	case "aes", "aes256", "Aes256GcmKey", "aes-256-gcm":
		return "Aes256GcmKey", true, nil
	default:
		return "", false, fmt.Errorf("unknown --type %q (want: secret | p256 | aes)", t)
	}
}

// mintVaultKeyGrant asks the platform to mint the grant for a new key and maps
// the response into the addressing the agent needs.
func mintVaultKeyGrant(ctx context.Context, client *api.Client, vaultID, name, keyType, cnf string, exportable bool) (string, secrets.VaultAddressing, error) {
	r, err := client.MintVaultKeyGrant(ctx, vaultID, name, keyType, cnf, exportable)
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

// vaultKeyAddressing builds the params to dial the constellation for an
// owner-authenticated op (sign / public) on an existing key.
func vaultKeyAddressing(ctx context.Context, cmd *cobra.Command, env *Env, client *api.Client, vaultID, name string) (secrets.VaultOpParams, error) {
	dir, err := client.VaultDirectory(ctx)
	if err != nil {
		return secrets.VaultOpParams{}, err
	}
	// The vault audience the owner principal is checked against.
	ownerTok, err := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "privasys-platform")
	if err != nil {
		return secrets.VaultOpParams{}, err
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
	return secrets.VaultOpParams{
		Handle:     "vaults/" + vaultID + "/" + name,
		Endpoints:  dir.Endpoints,
		MRENCLAVE:  dir.MRENCLAVE,
		AttServer:  dir.AttestationServer,
		AttToken:   attTok,
		OwnerToken: ownerTok,
	}, nil
}

func newVaultKeySignCmd() *cobra.Command {
	var fromFile string
	cmd := &cobra.Command{
		Use:   "sign <vault-id> <name> [message]",
		Short: "Sign a message with a vault signing key (in-enclave; key never leaves)",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			msg, err := resolveSignMessage(args, fromFile)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1])
			if err != nil {
				return err
			}
			res, err := secrets.SignInVault(cmd.Context(), p, msg)
			if err != nil {
				return err
			}
			sigB64 := base64.StdEncoding.EncodeToString(res.Signature)
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Signed (%s) on %s", res.Alg, res.Vault)
			}
			return output.Emit(env.Format, map[string]any{"alg": res.Alg, "vault": res.Vault, "signature_b64": sigB64}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"alg", res.Alg},
					{"signature", sigB64},
				}}
			})
		},
	}
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the message bytes from a file")
	return cmd
}

func resolveSignMessage(args []string, fromFile string) ([]byte, error) {
	if fromFile != "" {
		return os.ReadFile(fromFile)
	}
	if len(args) == 3 {
		return []byte(args[2]), nil
	}
	return nil, fmt.Errorf("provide a message argument or --from-file")
}

func newVaultKeyPublicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "public <vault-id> <name>",
		Short: "Print a vault key's public half as a JWK",
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
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1])
			if err != nil {
				return err
			}
			res, err := secrets.GetPublicKeyInVault(cmd.Context(), p)
			if err != nil {
				return err
			}
			jwk, err := jwkFromPublicKey(res.KeyType, res.PublicKey)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, jwk, func() output.Table {
				rows := [][]string{{"kty", fmt.Sprintf("%v", jwk["kty"])}, {"crv", fmt.Sprintf("%v", jwk["crv"])}}
				rows = append(rows, []string{"x", fmt.Sprintf("%v", jwk["x"])}, []string{"y", fmt.Sprintf("%v", jwk["y"])})
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
	return cmd
}

// jwkFromPublicKey encodes a vault public key as a JWK. A P-256 signing key's
// public material is the SEC1 uncompressed point (0x04 || X(32) || Y(32)).
func jwkFromPublicKey(keyType string, pub []byte) (map[string]any, error) {
	switch keyType {
	case "P256SigningKey":
		if len(pub) != 65 || pub[0] != 0x04 {
			return nil, fmt.Errorf("expected a 65-byte uncompressed P-256 point, got %d bytes", len(pub))
		}
		return map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(pub[1:33]),
			"y":   base64.RawURLEncoding.EncodeToString(pub[33:65]),
		}, nil
	default:
		return nil, fmt.Errorf("key type %q has no public key", keyType)
	}
}

func newVaultKeyWrapCmd() *cobra.Command {
	var fromFile string
	cmd := &cobra.Command{
		Use:   "wrap <vault-id> <name> [plaintext]",
		Short: "Encrypt data under a vault AES-256-GCM key (in-enclave; key never leaves)",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			pt, err := resolveSignMessage(args, fromFile)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1])
			if err != nil {
				return err
			}
			ct, iv, vaultEp, err := secrets.WrapInVault(cmd.Context(), p, pt, nil)
			if err != nil {
				return err
			}
			ctB64 := base64.StdEncoding.EncodeToString(ct)
			ivB64 := base64.StdEncoding.EncodeToString(iv)
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Wrapped on %s", vaultEp)
			}
			return output.Emit(env.Format, map[string]any{"ciphertext_b64": ctB64, "iv_b64": ivB64, "vault": vaultEp}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"ciphertext", ctB64},
					{"iv", ivB64},
				}}
			})
		},
	}
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read the plaintext bytes from a file")
	return cmd
}

func newVaultKeyUnwrapCmd() *cobra.Command {
	var ciphertextB64, ivB64 string
	cmd := &cobra.Command{
		Use:   "unwrap <vault-id> <name> --ciphertext <b64> --iv <b64>",
		Short: "Decrypt data under a vault AES-256-GCM key (in-enclave)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if ciphertextB64 == "" || ivB64 == "" {
				return fmt.Errorf("--ciphertext and --iv are required (base64)")
			}
			ct, err := base64.StdEncoding.DecodeString(ciphertextB64)
			if err != nil {
				return fmt.Errorf("--ciphertext: %w", err)
			}
			iv, err := base64.StdEncoding.DecodeString(ivB64)
			if err != nil {
				return fmt.Errorf("--iv: %w", err)
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1])
			if err != nil {
				return err
			}
			pt, vaultEp, err := secrets.UnwrapInVault(cmd.Context(), p, ct, iv, nil)
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Unwrapped on %s", vaultEp)
			}
			// Plaintext to stdout (raw) for table; base64 for json/yaml.
			if env.Format == "table" || env.Format == "" {
				cmd.OutOrStdout().Write(pt)
				if len(pt) > 0 && pt[len(pt)-1] != '\n' {
					cmd.OutOrStdout().Write([]byte("\n"))
				}
				return nil
			}
			return output.Emit(env.Format, map[string]any{"plaintext_b64": base64.StdEncoding.EncodeToString(pt), "vault": vaultEp}, nil)
		},
	}
	f := cmd.Flags()
	f.StringVar(&ciphertextB64, "ciphertext", "", "base64 ciphertext (from 'vault key wrap')")
	f.StringVar(&ivB64, "iv", "", "base64 IV (from 'vault key wrap')")
	return cmd
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
