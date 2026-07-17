// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/Privasys/cli/internal/output"
	"github.com/spf13/cobra"
)

// First-class volumes: an app's encrypted storage is an object you own,
// independent of the app. It is created at the first deploy (sized by
// --storage-gb, 10 GB default), bills per GB-hour at its provider/region rate
// whether attached or not, SURVIVES app deletion by default, and exists until
// you delete it here (or delete the app with --with-volume).

func newVolumesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "volumes",
		Aliases: []string{"volume", "vol"},
		Short:   "Manage your encrypted storage volumes",
		Long: `A volume is the encrypted storage behind a container app — owned by you,
independent of the app's lifecycle. Deleting an app keeps its volume (and its
billing) until you delete the volume; 'apps delete --with-volume' removes both.

Volumes are billed per GB-hour at the host provider/region's storage rate,
attached or not. Resize is online and grow-only.`,
	}
	c.AddCommand(
		newVolumesListCmd(),
		newVolumesDescribeCmd(),
		newVolumesResizeCmd(),
		newVolumesDeleteCmd(),
	)
	return c
}

func volumeRow(v map[string]interface{}) []string {
	size := fmt.Sprintf("%v GB", output.Str(v, "size_gb"))
	usage := ""
	if used := output.Str(v, "used_mb"); used != "" {
		usage = used + " MB used"
	}
	attached := "detached"
	if v["attached"] == true {
		attached = "attached"
	}
	app := output.Str(v, "app_name")
	if app == "" {
		app = "-"
	}
	return []string{
		output.Str(v, "id"), output.Str(v, "name"), size,
		output.Str(v, "provider") + "/" + output.Str(v, "region"),
		attached, app, usage, output.Str(v, "status"),
	}
}

func newVolumesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your volumes",
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
			vols, err := client.ListVolumes(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, vols, func() output.Table {
				t := output.Table{Headers: []string{"ID", "NAME", "SIZE", "LOCATION", "STATE", "APP", "USAGE", "STATUS"}}
				for _, v := range vols {
					t.Rows = append(t.Rows, volumeRow(v))
				}
				return t
			})
		},
	}
}

func newVolumesDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <volume-id>",
		Short: "Show a volume, including live used/free space",
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
			v, err := client.GetVolume(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, v, func() output.Table {
				return kvTable(v, []string{"id", "name", "size_gb", "provider", "region", "attached", "app_name", "used_mb", "avail_mb", "status", "usage_error", "created_at"})
			})
		},
	}
}

func newVolumesResizeCmd() *cobra.Command {
	var sizeGB int
	cmd := &cobra.Command{
		Use:   "resize <volume-id> --size-gb <gb>",
		Short: "Grow a volume (online; grow-only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if sizeGB <= 0 {
				return fmt.Errorf("--size-gb is required (the new total size; grow-only)")
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			v, err := client.ResizeVolume(cmd.Context(), args[0], sizeGB)
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Resized to %d GB", sizeGB)
			}
			return output.Emit(env.Format, v, func() output.Table {
				return kvTable(v, []string{"id", "name", "size_gb", "attached", "used_mb", "avail_mb"})
			})
		},
	}
	cmd.Flags().IntVar(&sizeGB, "size-gb", 0, "new total size in GB (must be larger than the current size)")
	return cmd
}

func newVolumesDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <volume-id>",
		Short: "Delete a volume — the encrypted data is destroyed and billing stops",
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
			if !yes {
				ok, cErr := confirm(cmd, env, "Delete this volume? Its encrypted data is destroyed and cannot be recovered (export your key first if you want the data).")
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			if err := client.DeleteVolume(cmd.Context(), args[0]); err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Volume deleted")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "delete without an interactive confirmation")
	return cmd
}
