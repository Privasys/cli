// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

// backupRepositoryInfo must match the runtime's backup.RepositoryInfo: it turns
// an app key into its backup repository password. Part of the owner's recovery
// contract; never change it.
const backupRepositoryInfo = "privasys/backup-repository/v1"

func newAppsKeyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "Manage your app's own storage key (BYOK)",
		Long: `An app created with --key-provider byok encrypts its storage, and its backups,
under a key YOU create and hold. The platform never sees it: the vaults each
keep a share, only your app's approved versions can reconstruct it, and the copy
you keep lets you re-create it on new vaults after a disaster, or open your
backups with stock kopia without Privasys at all.`,
	}
	c.AddCommand(newAppsKeyCreateCmd(), newAppsKeyBackupPasswordCmd())
	return c
}

func newAppsKeyCreateCmd() *cobra.Command {
	var out, fromFile, versionID, enclave string
	cmd := &cobra.Command{
		Use:   "create <app> --version <version-id> (--out <file> | --from-file <file>)",
		Short: "Create your app's storage key from material you hold",
		Long: `Creates the storage key of a BYOK app on the vault constellation, before its
first deploy. Either generate a new key (--out writes your copy, 0600, BEFORE
anything is sent, so the vaults never hold a key you do not) or bring your own
32-byte key (--from-file, e.g. from your HSM or 'apps export-key').

The key authorises --version on --enclave (default: the app's enclave); later
versions follow with 'apps versions stage' + 'promote'. Keep the file safe and
offline: it is the only way to recover the app's data and backups if the vaults
are lost.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (out == "") == (fromFile == "") {
				return fmt.Errorf("give exactly one of --out (generate a new key) or --from-file (bring your own)")
			}
			if versionID == "" {
				return fmt.Errorf("--version <version-id> is required: the key authorises that version")
			}
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			material, err := appKeyMaterial(out, fromFile)
			if err != nil {
				return err
			}
			defer zero(material)

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
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
			res, err := secrets.CreateAppKeyInVault(ctx, secrets.VaultCreateParams{
				Sub: sub, Secret: material, Exportable: true, AttToken: attTok,
				MintGrant: func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
					r, err := client.CreateAppKeyGrant(ctx, appID, cnf, enclave, versionID)
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
			fp := keyFingerprint(material)
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Created %s (%d/%d vaults, threshold %d, %s)",
					res.Handle, res.Created, res.Total, res.Threshold, fp)
				if out != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "Your key is in %s. Keep it safe and offline: it is the only way to recover this app's data and backups if the vaults are lost.\n", out)
				}
			}
			return output.Emit(env.Format, map[string]interface{}{
				"handle": res.Handle, "fingerprint": fp, "vaults": res.Created, "threshold": res.Threshold,
			}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", res.Handle},
					{"fingerprint", fp},
					{"vaults", fmt.Sprintf("%d/%d (threshold %d)", res.Created, res.Total, res.Threshold)},
				}}
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "", "generate a new key and write your copy to this file (0600; must not exist)")
	f.StringVar(&fromFile, "from-file", "", "bring your own key: a file holding the raw 32 bytes")
	f.StringVar(&versionID, "version", "", "the version the key authorises (its first deploy)")
	f.StringVar(&enclave, "enclave", "", "the enclave the first deploy runs on (default: the app's enclave)")
	return cmd
}

// appKeyMaterial generates a new key and writes the owner's copy first, or
// reads the owner's own key.
func appKeyMaterial(out, fromFile string) ([]byte, error) {
	if fromFile != "" {
		b, err := os.ReadFile(fromFile)
		if err != nil {
			return nil, err
		}
		if len(b) != secrets.AppKeySize {
			zero(b)
			return nil, fmt.Errorf("%s holds %d bytes; an app key is the raw %d bytes", fromFile, len(b), secrets.AppKeySize)
		}
		return b, nil
	}
	b := make([]byte, secrets.AppKeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		zero(b)
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%s already exists: refusing to overwrite a key file", out)
		}
		return nil, err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		zero(b)
		return nil, fmt.Errorf("write %s: %w", out, werr)
	}
	return b, nil
}

func newAppsKeyBackupPasswordCmd() *cobra.Command {
	var fromFile string
	cmd := &cobra.Command{
		Use:   "backup-password --from-file <key-file>",
		Short: "Print the backup repository password derived from your app key",
		Long: `Last-resort recovery without Privasys: prints the password of your app's backup
repository, derived locally from the key you hold:

    hex( HKDF-SHA256(key, salt = none, info = "privasys/backup-repository/v1", 32 bytes) )

With it, stock kopia opens the repository directly (S3 bucket, prefix
apps/<app-id>/), and 'kopia snapshot restore' gets your data back. The password
is printed to stdout and nothing else is sent anywhere.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromFile == "" {
				return fmt.Errorf("--from-file <key-file> is required")
			}
			key, err := appKeyMaterial("", fromFile)
			if err != nil {
				return err
			}
			defer zero(key)
			pw, err := backupRepositoryPassword(key)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), pw)
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFile, "from-file", "", "the file holding your raw 32-byte app key")
	return cmd
}

// backupRepositoryPassword mirrors the runtime's backup.RepositoryPassword.
func backupRepositoryPassword(key []byte) (string, error) {
	pw, err := hkdf.Key(sha256.New, key, nil, backupRepositoryInfo, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pw), nil
}

func keyFingerprint(material []byte) string {
	sum := sha256.Sum256(material)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
