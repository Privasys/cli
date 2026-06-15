// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

// creditsToGBP converts credits to pounds (1,000,000 credits = £1).
func creditsToGBP(credits float64) string {
	return fmt.Sprintf("£%.2f", credits/1_000_000)
}

func newBillingCmd() *cobra.Command {
	c := &cobra.Command{Use: "billing", Short: "View balance & usage; manage subscription and credits"}
	c.AddCommand(
		newBillingBalanceCmd(),
		newBillingUsageCmd(),
		newBillingLedgerCmd(),
		newBillingStatusCmd(),
		newBillingCheckoutCmd("subscribe", "membership", "Start/renew the annual platform membership"),
		newBillingCheckoutCmd("buy-credits", "credits", "Buy a pre-paid credit deposit"),
		newBillingPortalCmd(),
	)
	return c
}

func disabledNotice(env *Env) error {
	return output.Emit(env.Format, map[string]interface{}{"enabled": false},
		func() output.Table {
			return output.Table{Rows: [][]string{{"Billing is not enabled for this account/environment."}}}
		})
}

func newBillingBalanceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "balance",
		Short: "Show the credit balance",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.BillingBalance(cmd.Context())
			if err != nil {
				return err
			}
			if !res.Enabled {
				return disabledNotice(env)
			}
			return output.Emit(env.Format, res, func() output.Table {
				bal := numField(res.Data, "balance")
				return output.Table{
					Headers: []string{"FIELD", "VALUE"},
					Rows: [][]string{
						{"balance (credits)", fmt.Sprintf("%.0f", bal)},
						{"balance (GBP)", creditsToGBP(bal)},
						{"frozen", output.Str(res.Data, "frozen")},
					},
				}
			})
		},
	}
}

func newBillingUsageCmd() *cobra.Command {
	var since string
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "Show usage by resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.BillingUsage(cmd.Context(), since)
			if err != nil {
				return err
			}
			if !res.Enabled {
				return disabledNotice(env)
			}
			return output.Emit(env.Format, res, func() output.Table {
				rows := [][]string{}
				if list, ok := res.Data["by_resource"].([]interface{}); ok {
					for _, r := range list {
						rm, ok := r.(map[string]interface{})
						if !ok {
							continue
						}
						rows = append(rows, []string{
							output.Str(rm, "resource"),
							output.Str(rm, "quantity"),
							output.Str(rm, "calls"),
							fmt.Sprintf("%.0f (%s)", numField(rm, "credits"), creditsToGBP(numField(rm, "credits"))),
						})
					}
				}
				return output.Table{Headers: []string{"RESOURCE", "QUANTITY", "CALLS", "CREDITS (GBP)"}, Rows: rows}
			})
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only usage since this RFC3339 time")
	return cmd
}

func newBillingLedgerCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "ledger",
		Short: "Show the credit-ledger history",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.BillingLedger(cmd.Context(), limit)
			if err != nil {
				return err
			}
			if !res.Enabled {
				return disabledNotice(env)
			}
			return output.Emit(env.Format, res, func() output.Table {
				rows := [][]string{}
				if list, ok := res.Data["entries"].([]interface{}); ok {
					for _, e := range list {
						em, ok := e.(map[string]interface{})
						if !ok {
							continue
						}
						rows = append(rows, []string{
							output.Str(em, "ts"), output.Str(em, "kind"),
							output.Str(em, "credits"), output.Str(em, "reason"),
						})
					}
				}
				return output.Table{Headers: []string{"TIME", "KIND", "CREDITS", "REASON"}, Rows: rows}
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "max entries to return")
	return cmd
}

func newBillingStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the membership subscription state",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			sub, err := client.BillingSubscription(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, sub, func() output.Table {
				return output.Table{
					Headers: []string{"FIELD", "VALUE"},
					Rows: [][]string{
						{"enabled", output.Str(sub, "enabled")},
						{"status", output.Str(sub, "subscription_status")},
						{"active", output.Str(sub, "active")},
						{"period_end", output.Str(sub, "current_period_end")},
						{"cancel_at_period_end", output.Str(sub, "cancel_at_period_end")},
					},
				}
			})
		},
	}
}

// newBillingCheckoutCmd builds `subscribe` / `buy-credits`, which open a Stripe
// Checkout URL. The CLI never handles card data.
func newBillingCheckoutCmd(use, kind, short string) *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			url, enabled, err := client.Checkout(cmd.Context(), kind)
			if err != nil {
				return err
			}
			return emitURL(env, url, enabled, noBrowser, "Complete checkout in your browser:")
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the URL instead of opening a browser")
	return cmd
}

func newBillingPortalCmd() *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "portal",
		Short: "Open the Stripe billing portal (invoices, payment methods)",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			url, enabled, err := client.BillingPortal(cmd.Context())
			if err != nil {
				return err
			}
			return emitURL(env, url, enabled, noBrowser, "Manage billing in your browser:")
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the URL instead of opening a browser")
	return cmd
}

// emitURL handles the shared checkout/portal output: respect billing-disabled,
// emit the URL (json: {url}), and open a browser unless suppressed.
func emitURL(env *Env, url string, enabled, noBrowser bool, prompt string) error {
	if !enabled || url == "" {
		return disabledNotice(env)
	}
	if env.Format == "json" || env.Format == "yaml" {
		return output.Emit(env.Format, map[string]string{"url": url}, nil)
	}
	fmt.Printf("%s\n  %s\n", prompt, url)
	if !noBrowser && !env.NoInput {
		_ = openURL(url)
	}
	return nil
}

func numField(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}
