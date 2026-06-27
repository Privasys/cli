// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"os"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
)

func newAuthCmd() *cobra.Command {
	c := &cobra.Command{Use: "auth", Short: "Authenticate to the Privasys platform"}
	c.AddCommand(
		newAuthLoginCmd(),
		newAuthBeginCmd(),
		newAuthPollCmd(),
		newAuthActivateSACmd(),
		newAuthWhoamiCmd(),
		newAuthPrintTokenCmd(),
		newAuthListCmd(),
		newAuthLogoutCmd(),
	)
	return c
}

func newAuthLoginCmd() *cobra.Command {
	var noQR bool
	var force bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in with the Privasys Wallet (QR) — the default flow",
		Long:  "Starts a device authorization. Scan the QR with the Privasys Wallet (attestation-verified), or open the verification URL to use a passkey or social sign-in.",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			// Short-circuit when a valid (or silently refreshable) session
			// already exists, so re-running `login` doesn't start a fresh wallet
			// approval the user then has to complete for nothing. `--force`
			// re-authenticates regardless.
			if !force {
				if tok, aerr := auth.AccessToken(ctx, env.Cfg.Issuer); aerr == nil && tok != "" {
					output.Success(cmd.OutOrStdout(),
						"Already logged in%s (use --force to re-authenticate)", whom(subjectOf(tok)))
					return nil
				}
			}

			dr, verifier, err := auth.BeginDevice(ctx, env.Cfg.Issuer, auth.DefaultScope, "")
			if err != nil {
				return err
			}

			if !noQR && dr.QRPayload != "" {
				if q, qErr := qrcode.New(dr.QRPayload, qrcode.Low); qErr == nil {
					fmt.Println(q.ToSmallString(false))
				}
			}
			fmt.Printf("Scan the QR with your Privasys Wallet, or open:\n  %s\n  and enter code: %s\n\n",
				dr.VerificationURI, dr.UserCode)
			fmt.Println("Waiting for approval...")

			tr, err := auth.PollUntil(ctx, env.Cfg.Issuer, dr.DeviceCode, verifier, dr.Interval, dr.ExpiresIn)
			if err != nil {
				return err
			}
			if err := auth.SaveUserCredential(env.Cfg.Issuer, tr); err != nil {
				return err
			}
			sub := subjectOf(tr.AccessToken)
			output.Success(cmd.OutOrStdout(), "Logged in%s", whom(sub))
			return nil
		},
	}
	cmd.Flags().BoolVar(&noQR, "no-qr", false, "do not render the QR code")
	cmd.Flags().BoolVar(&force, "force", false, "re-authenticate even if already logged in")
	return cmd
}

func newAuthBeginCmd() *cobra.Command {
	var agent string
	var qr bool
	cmd := &cobra.Command{
		Use:   "begin",
		Short: "Begin an authorization for a human to approve (agent-brokered)",
		Long:  "Starts a device authorization and prints the verification URL + user code for you to surface to a human. The human approves on their wallet/browser; then run `privasys auth poll` (or poll programmatically) to obtain the token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			dr, verifier, err := auth.BeginDevice(cmd.Context(), env.Cfg.Issuer, auth.DefaultScope, agent)
			if err != nil {
				return err
			}
			_ = auth.SavePending(auth.PendingDevice{
				Issuer: env.Cfg.Issuer, DeviceCode: dr.DeviceCode, Verifier: verifier,
				UserCode: dr.UserCode, Interval: dr.Interval,
				ExpiresAt: time.Now().Add(time.Duration(dr.ExpiresIn) * time.Second),
			})
			if qr && dr.QRPayload != "" {
				if q, qErr := qrcode.New(dr.QRPayload, qrcode.Low); qErr == nil {
					fmt.Println(q.ToSmallString(false))
				}
			}
			view := map[string]interface{}{
				"verification_uri":          dr.VerificationURI,
				"verification_uri_complete": dr.VerificationURIComplete,
				"user_code":                 dr.UserCode,
				"expires_in":                dr.ExpiresIn,
				"interval":                  dr.Interval,
			}
			return output.Emit(env.Format, view, func() output.Table {
				return output.Table{
					Headers: []string{"FIELD", "VALUE"},
					Rows: [][]string{
						{"verification_uri", dr.VerificationURI},
						{"user_code", dr.UserCode},
						{"expires_in", fmt.Sprintf("%ds", dr.ExpiresIn)},
					},
				}
			})
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "name of the agent requesting access (shown to the user, unverified)")
	cmd.Flags().BoolVar(&qr, "qr", false, "also render the wallet QR code")
	return cmd
}

func newAuthPollCmd() *cobra.Command {
	var wait bool
	cmd := &cobra.Command{
		Use:   "poll",
		Short: "Complete a pending agent-brokered login",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			pend, err := auth.LoadPending()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			var tr *auth.TokenResponse
			if wait {
				secs := int(time.Until(pend.ExpiresAt).Seconds())
				tr, err = auth.PollUntil(ctx, pend.Issuer, pend.DeviceCode, pend.Verifier, pend.Interval, secs)
			} else {
				var t *auth.TokenResponse
				t, _, err = auth.PollOnce(ctx, pend.Issuer, pend.DeviceCode, pend.Verifier)
				if err == nil && t == nil {
					return fmt.Errorf("authorization_pending: not yet approved")
				}
				tr = t
			}
			if err != nil {
				return err
			}
			if err := auth.SaveUserCredential(pend.Issuer, tr); err != nil {
				return err
			}
			auth.RemovePending()
			_ = env
			output.Success(cmd.OutOrStdout(), "Logged in%s", whom(subjectOf(tr.AccessToken)))
			return nil
		},
	}
	cmd.Flags().BoolVar(&wait, "wait", false, "block until approved instead of polling once")
	return cmd
}

func newAuthActivateSACmd() *cobra.Command {
	var keyFile string
	cmd := &cobra.Command{
		Use:   "activate-service-account",
		Short: "Authenticate non-interactively with a service-account key",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if keyFile == "" {
				return fmt.Errorf("--key-file is required")
			}
			data, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("read key file: %w", err)
			}
			key, err := auth.ParseServiceKey(data)
			if err != nil {
				return err
			}
			// Verify the key works before saving.
			if _, err := auth.MintServiceAccountToken(cmd.Context(), env.Cfg.Issuer, key, auth.PlatformAudience); err != nil {
				return fmt.Errorf("service account verification failed: %w", err)
			}
			cred := &auth.Credential{
				Issuer:          env.Cfg.Issuer,
				ClientID:        auth.ClientID,
				Subject:         key.UserID,
				ServiceKey:      string(data),
				IsServiceKeyAcc: true,
			}
			if err := auth.Save(cred); err != nil {
				return err
			}
			output.Success(cmd.OutOrStdout(), "Activated service account %s", key.UserID)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "path to the service-account key JSON")
	return cmd
}

func newAuthWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the authenticated identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			token, err := auth.AccessToken(cmd.Context(), env.Cfg.Issuer)
			if err != nil {
				return err
			}
			claims, err := auth.Claims(token)
			if err != nil {
				return err
			}
			view := map[string]interface{}{
				"subject":  claims["sub"],
				"issuer":   claims["iss"],
				"audience": claims["aud"],
				"roles":    claims["roles"],
			}
			if email, ok := claims["email"]; ok {
				view["email"] = email
			}
			if exp, ok := claims["exp"].(float64); ok {
				view["expires"] = time.Unix(int64(exp), 0).Format(time.RFC3339)
			}
			return output.Emit(env.Format, view, func() output.Table {
				rows := [][]string{
					{"subject", fmt.Sprintf("%v", claims["sub"])},
					{"issuer", fmt.Sprintf("%v", claims["iss"])},
					{"audience", fmt.Sprintf("%v", claims["aud"])},
					{"roles", fmt.Sprintf("%v", claims["roles"])},
				}
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
}

func newAuthPrintTokenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "print-access-token",
		Short: "Print a valid access token (auto-refreshes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			token, err := auth.AccessToken(cmd.Context(), env.Cfg.Issuer)
			if err != nil {
				return err
			}
			fmt.Println(token)
			return nil
		},
	}
}

func newAuthListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			creds, err := auth.List()
			if err != nil {
				return err
			}
			return output.Emit(env.Format, creds, func() output.Table {
				rows := make([][]string, 0, len(creds))
				for _, c := range creds {
					kind := "wallet"
					if c.IsServiceKeyAcc {
						kind = "service-account"
					}
					rows = append(rows, []string{c.Issuer, c.Subject, kind})
				}
				return output.Table{Headers: []string{"ISSUER", "SUBJECT", "TYPE"}, Rows: rows}
			})
		},
	}
}

func newAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored credentials for the current issuer",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if err := auth.Delete(env.Cfg.Issuer); err != nil {
				return err
			}
			output.Success(cmd.OutOrStdout(), "Logged out")
			return nil
		},
	}
}

// --- helpers ---

func subjectOf(token string) string {
	claims, err := auth.Claims(token)
	if err != nil {
		return ""
	}
	if s, ok := claims["sub"].(string); ok {
		return s
	}
	return ""
}

func whom(sub string) string {
	if sub == "" {
		return ""
	}
	return " as " + sub
}
