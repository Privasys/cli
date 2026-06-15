// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
)

// resolveAppID accepts an app id (UUID) or name and returns the id. Names are
// resolved client-side (the API's /apps/{id} requires a UUID), so developers
// can use the friendly name everywhere.
func resolveAppID(ctx context.Context, client *api.Client, ref string) (string, error) {
	if isUUID(ref) {
		return ref, nil
	}
	apps, err := client.ListApps(ctx)
	if err != nil {
		return "", err
	}
	var match string
	for _, a := range apps {
		if output.Str(a, "name") == ref {
			if match != "" {
				return "", fmt.Errorf("multiple apps named %q; use the id", ref)
			}
			match = output.Str(a, "id")
		}
	}
	if match == "" {
		return "", fmt.Errorf("no app named %q (see `privasys apps list`)", ref)
	}
	return match, nil
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func newAppsCmd() *cobra.Command {
	c := &cobra.Command{Use: "apps", Short: "Manage confidential apps"}
	c.AddCommand(
		newAppsListCmd(),
		newAppsDescribeCmd(),
		newAppsCreateCmd(),
		newAppsDeleteCmd(),
		newAppsUploadCmd(),
		newAppsVersionsCmd(),
		newAppsDeployCmd(),
		newAppsUpgradeCmd(),
		newAppsDeploymentsCmd(),
		newAppsStopCmd(),
		newAppsAPICmd(),
		newAppsMcpCmd(),
		newAppsCallCmd(),
		newAppsBuildsCmd(),
		newAppsOwnersCmd(),
	)
	return c
}

// apiClient builds an authenticated platform API client for the invocation.
func apiClient(cmd *cobra.Command, env *Env) (*api.Client, error) {
	token, err := auth.AccessToken(cmd.Context(), env.Cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return api.New(env.Cfg.Endpoint, token), nil
}

func newAppsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			apps, err := client.ListApps(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, apps, func() output.Table {
				rows := make([][]string, 0, len(apps))
				for _, a := range apps {
					rows = append(rows, []string{
						output.Str(a, "name"),
						output.Str(a, "id"),
						appType(a),
						output.Str(a, "status"),
					})
				}
				return output.Table{Headers: []string{"NAME", "ID", "TYPE", "STATUS"}, Rows: rows}
			})
		},
	}
}

func newAppsDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <app-id>",
		Short: "Show an app's details (version, source, enclave, status)",
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
			app, err := client.GetApp(cmd.Context(), appID)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, app, func() output.Table {
				keys := []string{"name", "id", "app_type", "status", "owner_sub", "account_id",
					"github_repo", "github_branch", "commit", "image", "cwasm_hash", "enclave_id", "created_at"}
				rows := make([][]string, 0, len(keys))
				for _, k := range keys {
					if v := output.Str(app, k); v != "" {
						rows = append(rows, []string{k, v})
					}
				}
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
}

func appType(a map[string]interface{}) string {
	if v := output.Str(a, "app_type"); v != "" {
		return v
	}
	return output.Str(a, "type")
}
