// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/output"
)

func newAppsBackupCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "backup",
		Short: "Back up your app's volume, and list its restore points",
		Long: `Backups of a BYOK app's volume, run by the enclave that runs the app: encrypted
under a password derived from YOUR app key, deduplicated, and written to
immutable object storage. Restore with 'apps deploy --restore <id|latest>'.`,
	}
	c.AddCommand(
		newAppsBackupSimpleCmd("run", "Back the app's volume up now", (*api.Client).StartBackup),
		newAppsBackupSimpleCmd("list", "List the app's restore points", (*api.Client).ListBackups),
		newAppsBackupSimpleCmd("status", "Show the app's latest backup job", (*api.Client).BackupStatus),
	)
	return c
}

func newAppsBackupSimpleCmd(use, short string, call func(*api.Client, context.Context, string) (map[string]interface{}, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <app>",
		Short: short,
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
			ctx := cmd.Context()
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			v, err := call(client, ctx, appID)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, v, func() output.Table { return backupTable(v) })
		},
	}
}

// backupTable renders a job or a snapshot list.
func backupTable(v map[string]interface{}) output.Table {
	if snaps, ok := v["snapshots"].([]interface{}); ok {
		t := output.Table{Headers: []string{"ID", "TAKEN", "SIZE", "FILES", "KEPT AS"}}
		for _, s := range snaps {
			m, _ := s.(map[string]interface{})
			t.Rows = append(t.Rows, []string{output.Str(m, "id"), output.Str(m, "start_time"),
				output.Str(m, "size_bytes"), output.Str(m, "files"), fmt.Sprint(m["retention"])})
		}
		return t
	}
	job, _ := v["job"].(map[string]interface{})
	return kvTable(job, []string{"id", "state", "started_at", "finished_at", "error"})
}
