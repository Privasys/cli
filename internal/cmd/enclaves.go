// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

// newEnclavesCmd is the platform-fleet view. It is gated on the platform
// manager role (privasys-platform:manager); ordinary users get a 403 (exit 4).
func newEnclavesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "enclaves",
		Short: "Inspect the platform enclave fleet (platform managers only)",
		Long: `List and inspect the enclaves that make up the platform. This is a
platform-operator view over GET /api/v1/admin/enclaves and requires the
privasys-platform:manager role; without it the API returns not-authorized.`,
	}
	c.AddCommand(newEnclavesListCmd(), newEnclavesGetCmd())
	return c
}

func newEnclavesListCmd() *cobra.Command {
	var teeType, status string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the platform's enclaves",
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
			enclaves, err := client.ListEnclaves(cmd.Context())
			if err != nil {
				return err
			}
			// Optional client-side filters (the admin endpoint returns the full set).
			if teeType != "" || status != "" {
				filtered := enclaves[:0]
				for _, e := range enclaves {
					if teeType != "" && !strings.EqualFold(output.Str(e, "tee_type"), teeType) {
						continue
					}
					if status != "" && !strings.EqualFold(output.Str(e, "status"), status) {
						continue
					}
					filtered = append(filtered, e)
				}
				enclaves = filtered
			}
			return output.Emit(env.Format, enclaves, func() output.Table {
				rows := make([][]string, 0, len(enclaves))
				for _, e := range enclaves {
					rows = append(rows, []string{
						output.Str(e, "name"),
						output.Str(e, "id"),
						output.Str(e, "tee_type"),
						output.Str(e, "status"),
						enclaveLocation(e),
						output.Str(e, "tenancy"),
						enclaveApps(e),
						shortHex(output.Str(e, "mr_enclave")),
					})
				}
				return output.Table{
					Headers: []string{"NAME", "ID", "TEE", "STATUS", "LOCATION", "TENANCY", "APPS", "MEASUREMENT"},
					Rows:    rows,
				}
			})
		},
	}
	cmd.Flags().StringVar(&teeType, "tee", "", "filter by TEE type (sgx|tdx)")
	cmd.Flags().StringVar(&status, "status", "", "filter by status (e.g. active, pending)")
	return cmd
}

func newEnclavesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <enclave-id>",
		Short: "Show one enclave's full record",
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
			e, err := client.GetEnclave(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, e, func() output.Table {
				keys := []string{"name", "id", "tee_type", "status", "gateway_host", "port",
					"region", "country", "zone", "provider", "tenancy", "instance_power",
					"machine_shape", "owner_sub", "max_apps", "app_count", "mr_enclave",
					"os_release_tag", "os_release_status", "registered_at"}
				rows := make([][]string, 0, len(keys))
				for _, k := range keys {
					if v := output.Str(e, k); v != "" {
						rows = append(rows, []string{k, v})
					}
				}
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
}

// enclaveLocation renders a compact "region/country" (or whichever is present).
func enclaveLocation(e map[string]interface{}) string {
	region, country := output.Str(e, "region"), output.Str(e, "country")
	switch {
	case region != "" && country != "":
		return region + "/" + country
	case region != "":
		return region
	default:
		return country
	}
}

// enclaveApps renders "used/max" app slots.
func enclaveApps(e map[string]interface{}) string {
	max := output.Str(e, "max_apps")
	used := output.Str(e, "app_count")
	if max == "" && used == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s", used, max)
}

// shortHex truncates a long hex measurement for the table (JSON keeps the full value).
func shortHex(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
