package cmd

// Adopter hostnames in front of an app.
//
// An app can be reached at its owner's own hostname. In alias mode the
// gateway terminates TLS for it; in direct mode the gateway passes the
// connection through and the enclave presents its own certificate, so only
// the app's code sees the traffic. Direct mode needs the name in the app's
// signed policy (apps policy approve --domains) and a CAA record pinning the
// enclave's ACME account; switching prints that record when it is missing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
)

func newAppsDomainsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domains",
		Short: "Your own hostnames in front of the app, and where their TLS ends",
		Long: `Lists the hostnames an app has claimed and switches where their TLS ends.

  alias   the gateway terminates TLS with a certificate it obtains
  direct  the gateway passes the connection through; the enclave presents
          its own Let's Encrypt certificate, whose key never leaves it

Direct mode needs the hostname in the app's signed policy
(privasys apps policy approve <app> --domains <host>) and a CAA record that
pins issuance to the enclave's ACME account.`,
	}
	cmd.AddCommand(newAppsDomainsListCmd(), newAppsDomainsModeCmd())
	return cmd
}

func newAppsDomainsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <app>",
		Short: "List the app's hostnames, their mode and the CAA record direct mode needs",
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
			out, err := client.ListAppDomains(cmd.Context(), appID)
			if err != nil {
				return err
			}
			buf, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(buf))
			return nil
		},
	}
}

func newAppsDomainsModeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mode <app> <hostname> direct|alias",
		Short: "Switch where a hostname's TLS ends",
		Long: `Switches a claimed hostname to direct mode (TLS ends in the enclave) or back
to alias mode (TLS ends at the gateway).

Switching to direct checks that the hostname is proven, in the app's signed
policy, and covered by a CAA record pinning the enclave's ACME account. The
name then goes through direct-pending while the enclave obtains its
certificate, and becomes direct once the enclave serves it.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := strings.ToLower(args[2])
			if mode != "direct" && mode != "alias" {
				return fmt.Errorf("mode must be direct or alias, not %q", args[2])
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
			host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(args[1])), ".")
			out, err := client.SetAppDomainMode(cmd.Context(), appID, host, mode)
			if err != nil {
				return domainModeError(cmd, err)
			}
			got, _ := out["mode"].(string)
			if got == "direct-pending" {
				fmt.Fprintf(cmd.OutOrStdout(), "%s is direct-pending: the enclave is obtaining its certificate, and the name becomes direct once the enclave serves it\n", host)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is %s\n", host, got)
			return nil
		},
	}
}

// domainModeError turns a refused switch into its message, printing the CAA
// record to publish when that is what is missing.
func domainModeError(cmd *cobra.Command, err error) error {
	var se *api.StatusError
	if !errors.As(err, &se) {
		return err
	}
	var body struct {
		Error     string `json:"error"`
		CAARecord string `json:"caa_record"`
	}
	if se.Decode(&body) != nil || body.Error == "" {
		return err
	}
	if body.CAARecord != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Publish this CAA record, then switch again:")
		fmt.Fprintln(cmd.ErrOrStderr(), "  "+body.CAARecord)
	}
	return errors.New(body.Error)
}
