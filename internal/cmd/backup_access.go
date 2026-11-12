// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/output"
)

// Last-resort access: a read-only S3 key limited to one app's repository, so
// its owner can restore with stock kopia and the key they hold, without
// Privasys. The secret is returned once and the platform keeps no copy, so the
// CLI writes it to a file the owner names and never to the terminal, where an
// agent driving the CLI would read it. It is deliberately not an MCP tool.

// newBackupAccessCmd builds `access show|create|revoke`: under `apps backup`
// for a live app (live, by name or id), under `backups` for any app's kept
// backups, the app deleted or not (by id).
func newBackupAccessCmd(live bool) *cobra.Command {
	arg := "<app-id>"
	if live {
		arg = "<app>"
	}
	c := &cobra.Command{
		Use:   "access",
		Short: "Read-only keys to the app's backups, to restore with stock kopia without Privasys",
		Long: `A read-only S3 key that reaches this app's backup repository alone, for a
last-resort restore with stock kopia and your app key ('apps key
backup-password'), without Privasys. One key per app: creating one replaces the
previous key. The secret is shown once, so 'create' writes it to a file you
name; the platform keeps no copy.`,
	}
	c.AddCommand(newBackupAccessShowCmd(live, arg), newBackupAccessCreateCmd(live, arg), newBackupAccessRevokeCmd(live, arg))
	return c
}

// backupAccessTarget resolves the app: a live app by name or id; kept backups
// by id as given, since a deleted app no longer resolves by name.
func backupAccessTarget(cmd *cobra.Command, client *api.Client, live bool, ref string) (string, error) {
	if live {
		return resolveAppID(cmd.Context(), client, ref)
	}
	return ref, nil
}

func backupAccessTable(v map[string]interface{}) output.Table {
	return kvTable(v, []string{"exists", "access_key_id", "created_at", "endpoint", "region", "bucket", "prefix"})
}

func newBackupAccessShowCmd(live bool, arg string) *cobra.Command {
	return &cobra.Command{
		Use:   "show " + arg,
		Short: "Show whether the app's backups have a read-only key, and where they are",
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
			appID, err := backupAccessTarget(cmd, client, live, args[0])
			if err != nil {
				return err
			}
			v, err := client.GetBackupAccess(cmd.Context(), appID, live)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, v, func() output.Table { return backupAccessTable(v) })
		},
	}
}

func newBackupAccessCreateCmd(live bool, arg string) *cobra.Command {
	var out string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create " + arg + " --out <file>",
		Short: "Issue a read-only key to the app's backups, written to a file",
		Long: `Issues a read-only S3 key limited to this app's backup repository and writes it
to --out (0600; must not exist) as shell exports, then prints how to restore
with stock kopia. The secret never reaches the terminal. A key that already
exists is replaced: whoever holds it loses access, so you are asked first
(--yes skips the question).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return fmt.Errorf("--out <file> is required: the secret is written there, never shown")
			}
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			appID, err := backupAccessTarget(cmd, client, live, args[0])
			if err != nil {
				return err
			}
			cur, err := client.GetBackupAccess(ctx, appID, live)
			if err != nil {
				return err
			}
			if cur["exists"] == true && !yes {
				ok, cErr := confirm(cmd, env, fmt.Sprintf("Replace the read-only key %s? Whoever holds it loses access.", output.Str(cur, "access_key_id")))
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			// Claim the file before asking for the secret, which is shown once.
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				if os.IsExist(err) {
					return fmt.Errorf("%s already exists: refusing to overwrite it", out)
				}
				return err
			}
			v, err := client.CreateBackupAccess(ctx, appID, live)
			if err != nil {
				f.Close()
				os.Remove(out)
				return err
			}
			secret := output.Str(v, "secret_access_key")
			delete(v, "secret_access_key")
			if werr := writeBackupAccessFile(f, appID, output.Str(v, "access_key_id"), secret); werr != nil {
				return fmt.Errorf("the key was issued but could not be written to %s (%v): revoke it and create another", out, werr)
			}
			if warn := restrictKeyFile(out); warn != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning:", warn)
			}
			if !env.Quiet {
				fmt.Fprint(cmd.ErrOrStderr(), kopiaRecipe(out, v))
			}
			return output.Emit(env.Format, v, func() output.Table { return backupAccessTable(v) })
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "write the key to this file as shell exports (0600; must not exist)")
	cmd.Flags().BoolVar(&yes, "yes", false, "replace an existing key without asking")
	return cmd
}

func newBackupAccessRevokeCmd(live bool, arg string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "revoke " + arg,
		Short: "Delete the read-only key to the app's backups",
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
			appID, err := backupAccessTarget(cmd, client, live, args[0])
			if err != nil {
				return err
			}
			if !yes {
				ok, cErr := confirm(cmd, env, "Revoke the read-only key to these backups? Whoever holds it loses access.")
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			if err := client.RevokeBackupAccess(cmd.Context(), appID, live); err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Read-only backup access revoked")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "revoke without an interactive confirmation")
	return cmd
}

// writeBackupAccessFile writes the key as shell exports, then closes the file.
func writeBackupAccessFile(f *os.File, appID, keyID, secret string) error {
	_, err := fmt.Fprintf(f, "# Read-only access to the backups of app %s. Load it with: . <this file>\n"+
		"export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\n", appID, shellQuote(keyID), shellQuote(secret))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// kopiaRecipe is how to restore with the key, as the docs give it. It names
// the file, never the secret.
func kopiaRecipe(file string, v map[string]interface{}) string {
	var b strings.Builder
	w := io.Writer(&b)
	fmt.Fprintf(w, "Wrote the read-only key to %s. To restore without Privasys:\n", file)
	fmt.Fprintf(w, "  . %s\n", file)
	fmt.Fprintln(w, "  export KOPIA_PASSWORD=$(privasys apps key backup-password --from-file <your app key file>)")
	fmt.Fprintf(w, "  kopia repository connect s3 --bucket=%s --endpoint=%s --region=%s --prefix=%s --readonly --no-persist-credentials\n",
		output.Str(v, "bucket"), output.Str(v, "endpoint"), output.Str(v, "region"), output.Str(v, "prefix"))
	fmt.Fprintln(w, "  kopia snapshot list --all")
	fmt.Fprintln(w, "  kopia snapshot restore <snapshot-id> ./restored")
	return b.String()
}
