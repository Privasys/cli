// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

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
	c.AddCommand(newVaultCreateCmd(), newVaultListCmd(), newVaultRmCmd(), newVaultKeyCmd(), newVaultServeCmd())
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
		newVaultKeyWrapCmd(), newVaultKeyUnwrapCmd(), newVaultKeyRotateCmd(),
		newVaultKeyAuditCmd())
	return c
}

func newVaultKeyAuditCmd() *cobra.Command {
	var version, limit int
	cmd := &cobra.Command{
		Use:   "audit <vault-id> <name>",
		Short: "Show a key's audit log — every operation, who, allowed/denied (owner-readable)",
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
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1], version)
			if err != nil {
				return err
			}
			entries, vaultEp, err := secrets.ReadAuditInVault(cmd.Context(), p, limit)
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "%d audit entries from %s", len(entries), vaultEp)
			}
			return output.Emit(env.Format, entries, func() output.Table {
				rows := make([][]string, 0, len(entries))
				for _, e := range entries {
					ts := time.Unix(int64(e.Ts), 0).UTC().Format(time.RFC3339)
					rows = append(rows, []string{
						fmt.Sprintf("%d", e.Seq), ts, e.Op, e.Caller, e.Decision, e.Reason,
					})
				}
				return output.Table{Headers: []string{"SEQ", "TIME", "OP", "CALLER", "DECISION", "REASON"}, Rows: rows}
			})
		},
	}
	f := cmd.Flags()
	f.IntVar(&version, "version", 0, "key version (0 = current primary)")
	f.IntVar(&limit, "limit", 256, "max entries to return")
	return cmd
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
// resolveVaultKeyHandle resolves a key name to its constellation handle via the
// catalogue. version 0 = the current primary (highest version); version N pins a
// specific version (so data signed/wrapped under an old version still
// verifies/unwraps). Falls back to the v1 handle shape for uncatalogued keys.
func resolveVaultKeyHandle(ctx context.Context, client *api.Client, vaultID, name string, version int) (string, error) {
	keys, err := client.ListVaultKeys(ctx, vaultID)
	if err != nil {
		return "", err
	}
	best, bestV := "", -1
	for _, k := range keys {
		if fmt.Sprintf("%v", k["name"]) != name {
			continue
		}
		v := 0
		if vf, ok := k["version"].(float64); ok {
			v = int(vf)
		}
		h, _ := k["handle"].(string)
		if version > 0 {
			if v == version {
				return h, nil
			}
			continue
		}
		if v > bestV {
			bestV, best = v, h
		}
	}
	if best != "" {
		return best, nil
	}
	if version > 0 {
		return "", fmt.Errorf("version %d of key %q not found", version, name)
	}
	return "vaults/" + vaultID + "/" + name, nil // legacy / uncatalogued
}

func vaultKeyAddressing(ctx context.Context, cmd *cobra.Command, env *Env, client *api.Client, vaultID, name string, version int) (secrets.VaultOpParams, error) {
	dir, err := client.VaultDirectory(ctx)
	if err != nil {
		return secrets.VaultOpParams{}, err
	}
	handle, err := resolveVaultKeyHandle(ctx, client, vaultID, name, version)
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
		Handle:     handle,
		Endpoints:  dir.Endpoints,
		MRENCLAVE:  dir.MRENCLAVE,
		AttServer:  dir.AttestationServer,
		AttToken:   attTok,
		OwnerToken: ownerTok,
	}, nil
}

func newVaultKeySignCmd() *cobra.Command {
	var fromFile string
	var version int
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
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1], version)
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
	cmd.Flags().IntVar(&version, "version", 0, "key version to use (0 = current primary)")
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
	var version int
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
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1], version)
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
	cmd.Flags().IntVar(&version, "version", 0, "key version (0 = current primary)")
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
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1], 0)
			if err != nil {
				return err
			}
			ct, iv, vaultEp, err := secrets.WrapInVault(cmd.Context(), p, pt, nil, nil)
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
	var version int
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
			p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1], version)
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
	f.IntVar(&version, "version", 0, "key version that wrapped the data (0 = current primary)")
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
	var catalogueOnly bool
	cmd := &cobra.Command{
		Use:   "rm <vault-id> <name>",
		Short: "Delete a key — destroys the material on the constellation, then the catalogue entry",
		Long: `Deletes a key. By default it cryptographically destroys the key material on
the constellation (owner-authenticated DeleteKey, idempotent) and then removes
the catalogue entry. Use --catalogue-only to forget the key in your listing
without destroying the material on the vaults.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			deletedOn := []string{}
			if !catalogueOnly {
				p, err := vaultKeyAddressing(cmd.Context(), cmd, env, client, args[0], args[1], 0)
				if err != nil {
					return err
				}
				if deletedOn, err = secrets.DestroyKeyInVault(cmd.Context(), p); err != nil {
					return fmt.Errorf("destroy key material: %w", err)
				}
			}
			if err := client.DeleteVaultKey(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			if !env.Quiet {
				if catalogueOnly {
					output.Success(cmd.ErrOrStderr(), "Removed key %s from the catalogue (material left on the vaults)", args[1])
				} else {
					output.Success(cmd.ErrOrStderr(), "Deleted key %s (material destroyed on %d vault(s))", args[1], len(deletedOn))
				}
			}
			return output.Emit(env.Format, map[string]any{"deleted": true, "destroyed_on": deletedOn}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"deleted", "true"},
					{"material_destroyed_on", fmt.Sprintf("%d vault(s)", len(deletedOn))},
				}}
			})
		},
	}
	cmd.Flags().BoolVar(&catalogueOnly, "catalogue-only", false, "remove the catalogue entry only; leave the material on the vaults")
	return cmd
}

// getPrimaryVaultKeyType returns the key_type of a key's current primary version.
func getPrimaryVaultKeyType(ctx context.Context, client *api.Client, vaultID, name string) (string, error) {
	keys, err := client.ListVaultKeys(ctx, vaultID)
	if err != nil {
		return "", err
	}
	best, bestV := "", -1
	for _, k := range keys {
		if fmt.Sprintf("%v", k["name"]) != name {
			continue
		}
		v := 0
		if vf, ok := k["version"].(float64); ok {
			v = int(vf)
		}
		if v > bestV {
			bestV = v
			best, _ = k["key_type"].(string)
		}
	}
	if bestV < 0 {
		return "", fmt.Errorf("key %q not found in vault", name)
	}
	return best, nil
}

// rotateVaultKeyGrant asks the platform to mint a grant for a new key version and
// maps the response into the addressing the agent needs.
func rotateVaultKeyGrant(ctx context.Context, client *api.Client, vaultID, name, cnf string) (string, secrets.VaultAddressing, error) {
	r, err := client.RotateVaultKeyGrant(ctx, vaultID, name, cnf)
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

func newVaultKeyRotateCmd() *cobra.Command {
	var value, fromFile string
	var randomBytes int
	cmd := &cobra.Command{
		Use:   "rotate <vault-id> <name>",
		Short: "Create a new primary version of a key (old versions kept for verify/unwrap)",
		Long: `Rotates a key: creates a NEW primary version with fresh material, generated
client-side. Operations (sign/wrap) use the new primary; old versions are
retained so data signed/wrapped under them still verifies/unwraps (pin with
--version on sign/public/unwrap). For p256/aes keys the new material is generated
automatically; for a secret, provide --value/--from-file/--random-bytes.`,
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
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			vaultID, name := args[0], args[1]
			keyType, err := getPrimaryVaultKeyType(ctx, client, vaultID, name)
			if err != nil {
				return err
			}
			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
			mint := func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
				return rotateVaultKeyGrant(ctx, client, vaultID, name, cnf)
			}
			params := secrets.VaultCreateParams{Sub: sub, AttToken: attTok, MintGrant: mint}
			var res *secrets.Result
			switch keyType {
			case "P256SigningKey":
				res, err = secrets.CreateSigningKeyInVault(ctx, params)
			case "Aes256GcmKey":
				res, err = secrets.CreateAesKeyInVault(ctx, params)
			default:
				params.Exportable = true
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
				output.Success(cmd.ErrOrStderr(), "Rotated %s — new primary %s", name, res.Handle)
			}
			return output.Emit(env.Format, res, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"name", name},
					{"new_handle", res.Handle},
					{"type", keyType},
				}}
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&value, "value", "", "new secret value (secret keys only)")
	f.StringVar(&fromFile, "from-file", "", "read new secret bytes from a file (secret keys only)")
	f.IntVar(&randomBytes, "random-bytes", 32, "random bytes for a rotated secret when no value/file given")
	return cmd
}
