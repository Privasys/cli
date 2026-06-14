// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

func newAccountCmd() *cobra.Command {
	c := &cobra.Command{Use: "account", Short: "Manage your account (the billing & ownership boundary)"}
	c.AddCommand(newAccountShowCmd(), newAccountUpdateCmd())
	return c
}

func newAccountShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the current account and your role",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			view, err := client.GetAccount(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, view, func() output.Table {
				acct, _ := view["account"].(map[string]interface{})
				rows := [][]string{
					{"id", output.Str(acct, "id")},
					{"name", output.Str(acct, "name")},
					{"kind", output.Str(acct, "kind")},
					{"domain", output.Str(acct, "domain")},
					{"your role", output.Str(view, "role")},
				}
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
}

func newAccountUpdateCmd() *cobra.Command {
	var name, domain, kind string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the account (org name, domain, kind)",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			patch := map[string]interface{}{}
			putStr(patch, "name", name)
			putStr(patch, "domain", domain)
			putStr(patch, "kind", kind)
			if len(patch) == 0 {
				return fmt.Errorf("nothing to update (set --name, --domain, or --kind)")
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.UpdateAccount(cmd.Context(), patch)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Account updated.")
			return output.Emit(env.Format, res, nil)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "organisation name")
	cmd.Flags().StringVar(&domain, "domain", "", "organisation domain")
	cmd.Flags().StringVar(&kind, "kind", "", "account kind: individual|org")
	return cmd
}

func newTeamCmd() *cobra.Command {
	c := &cobra.Command{Use: "team", Short: "Manage account members"}
	c.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List account members",
			RunE: func(cmd *cobra.Command, args []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				client, err := apiClient(cmd, env)
				if err != nil {
					return err
				}
				res, err := client.ListMembers(cmd.Context())
				if err != nil {
					return err
				}
				return output.Emit(env.Format, res, func() output.Table { return membersTable(res) })
			},
		},
		newTeamAddCmd(),
		&cobra.Command{
			Use:   "set-role <sub> <admin|billing|member>",
			Short: "Change a member's role",
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
				res, err := client.SetMemberRole(cmd.Context(), args[0], args[1])
				if err != nil {
					return err
				}
				return output.Emit(env.Format, res, func() output.Table { return membersTable(res) })
			},
		},
		&cobra.Command{
			Use:   "remove <sub>",
			Short: "Remove a member",
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
				res, err := client.RemoveMember(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "Removed.")
				return output.Emit(env.Format, res, func() output.Table { return membersTable(res) })
			},
		},
	)
	return c
}

func newTeamAddCmd() *cobra.Command {
	var email, name, role string
	cmd := &cobra.Command{
		Use:   "add <sub>",
		Short: "Add an account member",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			member := map[string]interface{}{"sub": args[0]}
			putStr(member, "email", email)
			putStr(member, "name", name)
			putStr(member, "role", role)
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.AddMember(cmd.Context(), member)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table { return membersTable(res) })
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "member email")
	cmd.Flags().StringVar(&name, "name", "", "member name")
	cmd.Flags().StringVar(&role, "role", "member", "role: admin|billing|member")
	return cmd
}

// newAppsOwnersCmd manages per-app team access (the live API is /owners).
func newAppsOwnersCmd() *cobra.Command {
	c := &cobra.Command{Use: "owners", Short: "Manage who can access an app"}
	c.AddCommand(
		&cobra.Command{
			Use:   "list <app-id>",
			Short: "List app owners",
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
				res, err := client.ListAppOwners(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return output.Emit(env.Format, res, func() output.Table { return ownersTable(res) })
			},
		},
		newAppsOwnersAddCmd(),
		&cobra.Command{
			Use:   "remove <app-id> <sub>",
			Short: "Remove an app owner",
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
				res, err := client.RemoveAppOwner(cmd.Context(), args[0], args[1])
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "Removed.")
				return output.Emit(env.Format, res, func() output.Table { return ownersTable(res) })
			},
		},
	)
	return c
}

func newAppsOwnersAddCmd() *cobra.Command {
	var email, name string
	cmd := &cobra.Command{
		Use:   "add <app-id> <sub>",
		Short: "Grant a member access to an app",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			owner := map[string]interface{}{"sub": args[1]}
			putStr(owner, "email", email)
			putStr(owner, "name", name)
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.AddAppOwner(cmd.Context(), args[0], owner)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table { return ownersTable(res) })
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "member email")
	cmd.Flags().StringVar(&name, "name", "", "member name")
	return cmd
}

func ownersTable(res map[string]interface{}) output.Table {
	rows := [][]string{}
	if os, ok := res["owners"].([]interface{}); ok {
		for _, o := range os {
			om, ok := o.(map[string]interface{})
			if !ok {
				continue
			}
			rows = append(rows, []string{
				output.Str(om, "sub"), output.Str(om, "email"),
				output.Str(om, "name"), output.Str(om, "role"),
			})
		}
	}
	return output.Table{Headers: []string{"SUB", "EMAIL", "NAME", "ROLE"}, Rows: rows}
}

func membersTable(res map[string]interface{}) output.Table {
	rows := [][]string{}
	if ms, ok := res["members"].([]interface{}); ok {
		for _, m := range ms {
			mm, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			rows = append(rows, []string{
				output.Str(mm, "sub"), output.Str(mm, "email"),
				output.Str(mm, "name"), output.Str(mm, "role"),
			})
		}
	}
	return output.Table{Headers: []string{"SUB", "EMAIL", "NAME", "ROLE"}, Rows: rows}
}
