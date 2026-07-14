package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/output"
	"github.com/spf13/cobra"
)

// Dedicated instances (vm-billing Phase 6): a customer-owned confidential VM,
// managed independently of apps. Provision one, then `apps deploy --instance`
// several apps onto it.

func newInstancesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "instances",
		Aliases: []string{"instance", "vm"},
		Short:   "Manage dedicated confidential VM instances you own",
		Long: `A dedicated instance is a whole confidential VM you own — the strongest
isolation (your workloads get their own TD, not a cgroup). Provision one here,
then deploy any number of your apps onto it with:

    privasys apps deploy <app> --instance <instance-id>

The instance is the billed unit; the apps on it add no extra compute charge.`,
	}
	c.AddCommand(
		newInstancesCreateCmd(),
		newInstancesListCmd(),
		newInstancesDescribeCmd(),
		newInstancesStopCmd(),
		newInstancesStartCmd(),
		newInstancesDeleteCmd(),
	)
	return c
}

func newInstancesCreateCmd() *cobra.Command {
	var name, size, location string
	cmd := &cobra.Command{
		Use:   "create --size <size> [--name <name>] [--location <loc>]",
		Short: "Provision a dedicated instance (async; watch it for readiness)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if size == "" {
				return fmt.Errorf("--size is required (dedicated is offered for medium and large)")
			}
			slug, serr := normalizeInstanceSize(size)
			if serr != nil {
				return serr
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.CreateInstance(cmd.Context(), name, slug, location)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				inst, _ := res["instance"].(map[string]interface{})
				if msg := output.Str(res, "message"); msg != "" && !env.Quiet {
					fmt.Fprintln(cmd.OutOrStdout(), msg)
				}
				return instanceTable([]map[string]interface{}{inst})
			})
		},
	}
	cmd.Flags().StringVar(&size, "size", "", "instance size: medium | large")
	cmd.Flags().StringVar(&name, "name", "", "friendly name for the instance")
	cmd.Flags().StringVar(&location, "location", "", "location (Paris only at launch)")
	return cmd
}

func newInstancesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the dedicated instances you own",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			insts, err := client.ListInstances(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, map[string]interface{}{"instances": insts}, func() output.Table {
				return instanceTable(insts)
			})
		},
	}
}

func newInstancesDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "describe <instance>",
		Aliases: []string{"show", "get"},
		Short:   "Show an instance and the apps deployed on it",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			id, err := resolveInstanceID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			res, err := client.GetInstance(cmd.Context(), id)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				inst, _ := res["instance"].(map[string]interface{})
				return instanceTable([]map[string]interface{}{inst})
			})
		},
	}
}

func newInstancesStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <instance>",
		Short: "Stop the instance VM (compute billing stops; data retained)",
		Args:  cobra.ExactArgs(1),
		RunE:  instanceActionRunE(func(c *api.Client, ctx context.Context, id string) (map[string]interface{}, error) { return c.StopInstance(ctx, id) }),
	}
}

func newInstancesStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <instance>",
		Short: "Start a stopped instance (it re-registers on boot)",
		Args:  cobra.ExactArgs(1),
		RunE:  instanceActionRunE(func(c *api.Client, ctx context.Context, id string) (map[string]interface{}, error) { return c.StartInstance(ctx, id) }),
	}
}

func newInstancesDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <instance>",
		Short: "Delete the instance VM (disks retained per the retention policy)",
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
			id, err := resolveInstanceID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			ok, err := confirm(cmd, env, fmt.Sprintf("Delete instance %s? The VM is removed; disks are retained.", args[0]))
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			res, err := client.DeleteInstance(cmd.Context(), id, force)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				if msg := output.Str(res, "message"); msg != "" {
					fmt.Fprintln(cmd.OutOrStdout(), msg)
				}
				return output.Table{}
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete even while apps are still deployed on it")
	return cmd
}

// instanceActionRunE is the shared RunE for the simple stop/start verbs.
func instanceActionRunE(action func(*api.Client, context.Context, string) (map[string]interface{}, error)) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		env, err := loadEnv(cmd)
		if err != nil {
			return err
		}
		client, err := apiClient(cmd, env)
		if err != nil {
			return err
		}
		id, err := resolveInstanceID(cmd.Context(), client, args[0])
		if err != nil {
			return err
		}
		res, err := action(client, cmd.Context(), id)
		if err != nil {
			return err
		}
		return output.Emit(env.Format, res, func() output.Table {
			inst, _ := res["instance"].(map[string]interface{})
			return instanceTable([]map[string]interface{}{inst})
		})
	}
}

// resolveInstanceID accepts an instance id or a friendly name and returns the
// id. Names are matched against the caller's instances (case-insensitive).
func resolveInstanceID(ctx context.Context, client *api.Client, ref string) (string, error) {
	if isUUID(ref) {
		return ref, nil
	}
	insts, err := client.ListInstances(ctx)
	if err != nil {
		return "", err
	}
	var match string
	for _, in := range insts {
		if strings.EqualFold(output.Str(in, "name"), ref) {
			if match != "" {
				return "", fmt.Errorf("multiple instances named %q; use the id", ref)
			}
			match = output.Str(in, "id")
		}
	}
	if match == "" {
		return "", fmt.Errorf("no instance %q found", ref)
	}
	return match, nil
}

func instanceTable(insts []map[string]interface{}) output.Table {
	rows := make([][]string, 0, len(insts))
	for _, in := range insts {
		if in == nil {
			continue
		}
		host := output.Str(in, "host")
		if host == "" {
			host = "-"
		}
		rows = append(rows, []string{
			output.Str(in, "id"),
			output.Str(in, "name"),
			output.Str(in, "shape"),
			output.Str(in, "state"),
			fmt.Sprintf("%d", int64(numField(in, "app_count"))),
			host,
		})
	}
	return output.Table{
		Headers: []string{"ID", "NAME", "SHAPE", "STATE", "APPS", "HOST"},
		Rows:    rows,
	}
}
