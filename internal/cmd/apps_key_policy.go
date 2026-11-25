// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/secrets"
)

func newAppsTCBPolicyCmd() *cobra.Command {
	var accept []string
	var strict, yes bool
	cmd := &cobra.Command{
		Use:   "tcb-policy <app> (--accept <status> ... | --strict)",
		Short: "Set which Intel TCB statuses may unlock the app's data key",
		Long: `Arms the acceptable Intel TCB statuses on every measurement of the app's
data key. A platform whose attestation reports another status cannot unlock it.

--strict accepts only the floor (UpToDate and SWHardeningNeeded). --accept adds
a status to the floor, for example ConfigurationAndSWHardeningNeeded; repeat it
for several. "Revoked" is never accepted.

The key's vaults ask for your approval in the Privasys Wallet when its policy
requires one; the CLI checks the change against every vault before you approve
it, and checks the result afterwards.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strict == (len(accept) > 0) {
				return fmt.Errorf("pass either --strict or one or more --accept <status>")
			}
			statuses := []string{}
			if !strict {
				statuses = accept
			}
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
			what := "Accept only the TCB floor (UpToDate, SWHardeningNeeded) for this key"
			if !strict {
				what = "Accept the TCB floor plus " + strings.Join(statuses, ", ") + " for this key"
			}
			if !yes {
				ok, cErr := confirm(cmd, env, what+" on "+args[0]+"? [y/N] ")
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			res, err := changeKeyPolicy(cmd, env, client, appID, keyPolicyChange{
				summary: what,
				expect: func(current json.RawMessage) (json.RawMessage, error) {
					return secrets.ExpectTCBPolicy(current, statuses)
				},
				call: func(c *api.Client, newPolicy json.RawMessage) (map[string]interface{}, error) {
					return c.SetTCBPolicy(cmd.Context(), appID, statuses, newPolicy)
				},
			})
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "%s", what)
			}
			return output.Emit(env.Format, res, func() output.Table {
				return kvTable(res, []string{"acceptable_tcb_statuses", "all_succeeded", "checked", "warning"})
			})
		},
	}
	cmd.Flags().StringArrayVar(&accept, "accept", nil, "a TCB status to accept beyond the floor (repeatable)")
	cmd.Flags().BoolVar(&strict, "strict", false, "accept only the floor (UpToDate, SWHardeningNeeded)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

func newAppsAutoMigrateCmd() *cobra.Command {
	var on, off, yes bool
	cmd := &cobra.Command{
		Use:   "auto-migrate <app> (--on | --off)",
		Short: "Let the app's data key follow a platform upgrade of the same app code",
		Long: `With --on, the vaults release the app's data key to a platform-staged
measurement that differs from an approved one only in the runtime (the same app
code and app id), without a new promote. --off requires your promote again for
every new measurement.

The key's vaults ask for your approval in the Privasys Wallet when its policy
requires one; the CLI checks the change against every vault before you approve
it, and checks the result afterwards.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if on == off {
				return fmt.Errorf("pass either --on or --off")
			}
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
			what := "Let this key follow a platform upgrade of the same app code"
			if off {
				what = "Require a promote for every new measurement of this key"
			}
			if !yes {
				ok, cErr := confirm(cmd, env, what+" ("+args[0]+")? [y/N] ")
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			res, err := changeKeyPolicy(cmd, env, client, appID, keyPolicyChange{
				summary: what,
				expect:  func(current json.RawMessage) (json.RawMessage, error) { return secrets.ExpectAutoMigrate(current, on) },
				call: func(c *api.Client, newPolicy json.RawMessage) (map[string]interface{}, error) {
					return c.SetAutoMigrate(cmd.Context(), appID, on, newPolicy)
				},
			})
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "%s", what)
			}
			return output.Emit(env.Format, res, func() output.Table {
				return kvTable(res, []string{"auto_migrate", "all_succeeded", "checked", "warning"})
			})
		},
	}
	cmd.Flags().BoolVar(&on, "on", false, "turn auto-migrate on")
	cmd.Flags().BoolVar(&off, "off", false, "turn auto-migrate off")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}
