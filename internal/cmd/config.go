// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

func newConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI configuration",
	}
	c.AddCommand(
		&cobra.Command{
			Use:   "set <key> <value>",
			Short: "Set a configuration value (endpoint, issuer, account, format)",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				if err := env.File.Set(args[0], args[1]); err != nil {
					return err
				}
				if !env.Quiet {
					fmt.Printf("Set %s = %s\n", args[0], args[1])
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "get <key>",
			Short: "Get a configuration value",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				v, err := env.File.Get(args[0])
				if err != nil {
					return err
				}
				fmt.Println(v)
				return nil
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "Show the active configuration",
			RunE: func(cmd *cobra.Command, args []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				view := map[string]string{
					"endpoint": env.Cfg.Endpoint,
					"issuer":   env.Cfg.Issuer,
					"account":  env.Cfg.Account,
					"format":   env.Format,
				}
				return output.Emit(env.Format, view, func() output.Table {
					return output.Table{
						Headers: []string{"KEY", "VALUE"},
						Rows: [][]string{
							{"endpoint", env.Cfg.Endpoint},
							{"issuer", env.Cfg.Issuer},
							{"account", env.Cfg.Account},
							{"format", env.Format},
						},
					}
				})
			},
		},
	)
	return c
}
