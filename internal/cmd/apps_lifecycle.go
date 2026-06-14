// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/output"
)

func newAppsCreateCmd() *cobra.Command {
	var (
		name, displayName, description string
		source, appType                string
		commitURL, image               string
		port                           int
		storage                        bool
		cloudImageName, cloudChannel   string
		enclave                        string
	)
	cmd := &cobra.Command{
		Use:   "create --name <name> --source <upload|github|package|cloud_image> [flags]",
		Short: "Create a new app",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if name == "" || source == "" {
				return fmt.Errorf("--name and --source are required")
			}
			body := map[string]interface{}{"name": name, "source_type": source}
			putStr(body, "display_name", displayName)
			putStr(body, "description", description)
			putStr(body, "app_type", appType)
			putStr(body, "commit_url", commitURL)
			putStr(body, "container_image", image)
			putStr(body, "cloud_image_name", cloudImageName)
			putStr(body, "cloud_image_channel", cloudChannel)
			putStr(body, "enclave_id", enclave)
			if port != 0 {
				body["container_port"] = port
			}
			if storage {
				body["container_storage"] = true
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			app, err := client.CreateApp(cmd.Context(), body)
			if err != nil {
				return err
			}
			if !env.Quiet {
				fmt.Fprintf(os.Stderr, "Created app %s (%s)\n", output.Str(app, "name"), output.Str(app, "id"))
			}
			return output.Emit(env.Format, app, func() output.Table {
				return kvTable(app, []string{"name", "id", "app_type", "source_type", "status"})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "app name (DNS-safe)")
	f.StringVar(&displayName, "display-name", "", "human-friendly name")
	f.StringVar(&description, "description", "", "description")
	f.StringVar(&source, "source", "", "source type: upload|github|package|cloud_image")
	f.StringVar(&appType, "type", "", "app type: wasm|container")
	f.StringVar(&commitURL, "commit-url", "", "GitHub commit URL (github source)")
	f.StringVar(&image, "image", "", "container image ref (package source)")
	f.IntVar(&port, "port", 0, "container port (container apps)")
	f.BoolVar(&storage, "storage", false, "request encrypted container storage")
	f.StringVar(&cloudImageName, "cloud-image-name", "", "cloud image name (cloud_image source)")
	f.StringVar(&cloudChannel, "cloud-image-channel", "", "cloud image channel (cloud_image source)")
	f.StringVar(&enclave, "enclave", "", "target enclave id")
	return cmd
}

func newAppsDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <app-id>",
		Short: "Delete an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if !force && !env.NoInput {
				fmt.Fprintf(os.Stderr, "Delete app %s? Re-run with --force to confirm.\n", args[0])
				return fmt.Errorf("confirmation required")
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			if err := client.DeleteApp(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Deleted.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete without confirmation")
	return cmd
}

func newAppsUploadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload <app-id> <file.cwasm>",
		Short: "Upload a .cwasm artifact (wasm apps)",
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
			app, err := client.UploadCwasm(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Uploaded.")
			return output.Emit(env.Format, app, func() output.Table {
				return kvTable(app, []string{"name", "id", "cwasm_hash", "cwasm_size", "status"})
			})
		},
	}
}

func newAppsVersionsCmd() *cobra.Command {
	c := &cobra.Command{Use: "versions", Short: "Manage app versions"}
	c.AddCommand(
		&cobra.Command{
			Use:   "list <app-id>",
			Short: "List versions",
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
				vs, err := client.ListVersions(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return output.Emit(env.Format, vs, func() output.Table {
					rows := make([][]string, 0, len(vs))
					for _, v := range vs {
						rows = append(rows, []string{
							output.Str(v, "version_number"), output.Str(v, "id"),
							output.Str(v, "github_commit"), output.Str(v, "status"),
						})
					}
					return output.Table{Headers: []string{"VERSION", "ID", "COMMIT", "STATUS"}, Rows: rows}
				})
			},
		},
		&cobra.Command{
			Use:   "create <app-id> --commit-url <url>",
			Short: "Record a new version from a commit (triggers a build)",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				commitURL, _ := cmd.Flags().GetString("commit-url")
				if commitURL == "" {
					return fmt.Errorf("--commit-url is required")
				}
				client, err := apiClient(cmd, env)
				if err != nil {
					return err
				}
				v, err := client.CreateVersion(cmd.Context(), args[0], commitURL)
				if err != nil {
					return err
				}
				return output.Emit(env.Format, v, func() output.Table {
					return kvTable(v, []string{"version_number", "id", "github_commit", "status"})
				})
			},
		},
	)
	c.PersistentFlags().String("commit-url", "", "GitHub commit URL")
	return c
}

func newAppsDeployCmd() *cobra.Command {
	var versionID, enclaveID string
	var watch bool
	cmd := &cobra.Command{
		Use:   "deploy <app-id>",
		Short: "Deploy a version to an enclave",
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
			appID := args[0]

			// Default to the latest version when not specified.
			if versionID == "" {
				vs, err := client.ListVersions(cmd.Context(), appID)
				if err != nil {
					return err
				}
				if len(vs) == 0 {
					return fmt.Errorf("no versions; create one with `apps versions create` or `apps upload`")
				}
				versionID = output.Str(vs[len(vs)-1], "id")
			}

			// Resolve a compatible enclave when not specified.
			if enclaveID == "" {
				encs, err := client.CompatibleEnclaves(cmd.Context(), appID)
				if err != nil {
					return err
				}
				if len(encs) == 1 {
					enclaveID = output.Str(encs[0], "id")
				} else if len(encs) == 0 {
					return fmt.Errorf("no compatible enclaves available")
				} else {
					if env.NoInput {
						return fmt.Errorf("multiple compatible enclaves; pass --enclave <id>")
					}
					return fmt.Errorf("multiple compatible enclaves; pass --enclave <id> (see `apps deploy --help`)")
				}
			}

			dep, err := client.DeployVersion(cmd.Context(), appID, versionID, enclaveID)
			if err != nil {
				return err
			}
			if !watch {
				return output.Emit(env.Format, dep, func() output.Table {
					return kvTable(dep, []string{"id", "status", "enclave_host", "hostname"})
				})
			}
			return watchDeployment(cmd, client, env, appID, output.Str(dep, "id"))
		},
	}
	cmd.Flags().StringVar(&versionID, "version", "", "version id (default: latest)")
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "target enclave id (default: the only compatible one)")
	cmd.Flags().BoolVar(&watch, "watch", false, "poll until the deployment is active or failed")
	return cmd
}

func watchDeployment(cmd *cobra.Command, client *api.Client, env *Env, appID, depID string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		deps, err := client.ListDeployments(cmd.Context(), appID)
		if err != nil {
			return err
		}
		var cur map[string]interface{}
		for _, d := range deps {
			if output.Str(d, "id") == depID {
				cur = d
				break
			}
		}
		if cur != nil {
			st := output.Str(cur, "status")
			cs := output.Str(cur, "container_state")
			fmt.Fprintf(os.Stderr, "status=%s%s\n", st, ifPresent(" container=", cs))
			switch st {
			case "active", "deployed", "running":
				return output.Emit(env.Format, cur, func() output.Table {
					return kvTable(cur, []string{"id", "status", "container_state", "enclave_host", "hostname"})
				})
			case "failed", "error", "stopped":
				return fmt.Errorf("deployment %s ended in status %q", depID, st)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out watching deployment %s", depID)
		}
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func newAppsDeploymentsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deployments <app-id>",
		Short: "List an app's deployments",
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
			deps, err := client.ListDeployments(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, deps, func() output.Table {
				rows := make([][]string, 0, len(deps))
				for _, d := range deps {
					rows = append(rows, []string{
						output.Str(d, "id"), output.Str(d, "status"),
						output.Str(d, "container_state"), output.Str(d, "enclave_host"),
					})
				}
				return output.Table{Headers: []string{"ID", "STATUS", "CONTAINER", "ENCLAVE"}, Rows: rows}
			})
		},
	}
}

func newAppsStopCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "stop <app-id> <deployment-id>",
		Short: "Stop a running deployment",
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
			dep, err := client.StopDeployment(cmd.Context(), args[0], args[1], force)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, dep, func() output.Table {
				return kvTable(dep, []string{"id", "status"})
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "force stop")
	return cmd
}

func newAppsAPICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api <app-id>",
		Short: "List the app's exported functions (schema)",
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
			schema, err := client.Schema(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, schema, func() output.Table {
				rows := schemaRows(schema)
				return output.Table{Headers: []string{"INTERFACE", "FUNCTION", "PARAMS", "RESULTS"}, Rows: rows}
			})
		},
	}
}

func newAppsMcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp <app-id>",
		Short: "Show the app's MCP tool manifest",
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
			m, err := client.MCP(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, m, nil)
		},
	}
}

func newAppsCallCmd() *cobra.Command {
	var data string
	cmd := &cobra.Command{
		Use:   "call <app-id> <function>",
		Short: "Call an app function (RPC)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			var body interface{}
			if data != "" {
				raw := []byte(data)
				if len(data) > 1 && data[0] == '@' {
					b, rerr := os.ReadFile(data[1:])
					if rerr != nil {
						return rerr
					}
					raw = b
				}
				if err := json.Unmarshal(raw, &body); err != nil {
					return fmt.Errorf("--data is not valid JSON: %w", err)
				}
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.RPC(cmd.Context(), args[0], args[1], body)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, nil)
		},
	}
	cmd.Flags().StringVar(&data, "data", "", "JSON request body, or @file to read from a file")
	return cmd
}

func newAppsBuildsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "builds <app-id>",
		Short: "List build jobs",
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
			builds, err := client.ListBuilds(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, builds, func() output.Table {
				rows := make([][]string, 0, len(builds))
				for _, b := range builds {
					rows = append(rows, []string{
						output.Str(b, "id"), output.Str(b, "status"),
						output.Str(b, "github_commit"), output.Str(b, "run_url"),
					})
				}
				return output.Table{Headers: []string{"ID", "STATUS", "COMMIT", "RUN"}, Rows: rows}
			})
		},
	}
}

// --- helpers ---

func putStr(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func kvTable(m map[string]interface{}, keys []string) output.Table {
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		if v := output.Str(m, k); v != "" {
			rows = append(rows, []string{k, v})
		}
	}
	return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

func ifPresent(prefix, v string) string {
	if v == "" {
		return ""
	}
	return prefix + v
}

// schemaRows flattens an app schema (top-level functions + interfaces) into
// table rows.
func schemaRows(schema map[string]interface{}) [][]string {
	var rows [][]string
	addFns := func(iface string, fns []interface{}) {
		for _, fn := range fns {
			fm, ok := fn.(map[string]interface{})
			if !ok {
				continue
			}
			rows = append(rows, []string{iface, output.Str(fm, "name"), countOf(fm, "params"), countOf(fm, "results")})
		}
	}
	if fns, ok := schema["functions"].([]interface{}); ok {
		addFns("", fns)
	}
	if ifaces, ok := schema["interfaces"].([]interface{}); ok {
		for _, i := range ifaces {
			im, ok := i.(map[string]interface{})
			if !ok {
				continue
			}
			if fns, ok := im["functions"].([]interface{}); ok {
				addFns(output.Str(im, "name"), fns)
			}
		}
	}
	return rows
}

func countOf(m map[string]interface{}, key string) string {
	if a, ok := m[key].([]interface{}); ok {
		return fmt.Sprintf("%d", len(a))
	}
	return "0"
}
