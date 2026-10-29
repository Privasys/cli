// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/Privasys/cli/internal/output"
	"github.com/spf13/cobra"
)

// An app's backups outlive it, as its volume does: deleting the app keeps its
// backup repository (and its billing) until the owner deletes it here, or
// deletes the app with --with-backups. 'apps backup' works on a live app;
// 'backups' lists every repository the owner has, deleted apps included.

func newBackupsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "backups",
		Aliases: []string{"backup"},
		Short:   "List and delete your backups, including those of deleted apps",
		Long: `Every BYOK app with backups has a repository of restore points. Deleting the
app keeps it (and its billing) until you delete it here; 'apps delete
--with-backups' removes both. Backups are billed per stored GB-hour.

To back a live app up or change its schedule, use 'apps backup'.`,
	}
	c.AddCommand(
		newBackupsListCmd(),
		newBackupsShowCmd(),
		newBackupsDeleteCmd(),
	)
	return c
}

func newBackupsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your backup repositories, one per app",
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
			v, err := client.ListBackupSets(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, v, func() output.Table {
				t := output.Table{Headers: []string{"APP ID", "APP", "SNAPSHOTS", "STORED", "UPDATED", "APP STATE"}}
				sets, _ := v["backups"].([]interface{})
				for _, s := range sets {
					m, _ := s.(map[string]interface{})
					state := "live"
					if d := output.Str(m, "app_deleted_at"); d != "" {
						state = "deleted " + d
					}
					t.Rows = append(t.Rows, []string{output.Str(m, "app_id"), output.Str(m, "app_name"),
						output.Str(m, "snapshots"), output.Str(m, "stored_bytes"), output.Str(m, "updated_at"), state})
				}
				return t
			})
		},
	}
}

func newBackupsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <app-id>",
		Short: "Show an app's restore points, the app deleted or not",
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
			// A deleted app no longer resolves by name: take the id as given.
			v, err := client.GetBackupSet(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, v, func() output.Table { return backupTable(v) })
		},
	}
}

func newBackupsDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <app-id>",
		Short: "Delete a deleted app's backups: its restore points are destroyed and billing stops",
		Long: `Deletes every restore point of an app you have deleted, and stops their
billing. A live app's backups are deleted with the app ('apps delete
--with-backups'), so the platform refuses this while the app exists.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			if !yes {
				ok, cErr := confirm(cmd, env, "Delete these backups? Every restore point is destroyed and cannot be recovered.")
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			if err := client.DeleteBackupSet(cmd.Context(), args[0]); err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Backups deleted")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "delete without an interactive confirmation")
	return cmd
}
