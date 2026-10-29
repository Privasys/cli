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
	cmd.AddCommand(newAppsDomainsListCmd(), newAppsDomainsAddCmd(), newAppsDomainsVerifyCmd(),
		newAppsDomainsRemoveCmd(), newAppsDomainsModeCmd())
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
				fmt.Fprintf(cmd.OutOrStdout(), "%s is direct-pending.\n", host)
				fmt.Fprintln(cmd.OutOrStdout(), "Next: the gateway now passes the certificate challenge to the enclave, which")
				fmt.Fprintln(cmd.OutOrStdout(), "obtains its own certificate, usually within a few minutes. The control plane")
				fmt.Fprintln(cmd.OutOrStdout(), "checks every minute and switches the name to direct once the enclave serves it.")
				fmt.Fprintf(cmd.OutOrStdout(), "Follow it with: privasys apps domains list %s\n", args[0])
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

func newAppsDomainsAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <app> <hostname>",
		Short: "Claim one of your hostnames for the app and print the DNS records it needs",
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
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			host := normaliseDomainArg(args[1])
			out, err := client.AddAppDomain(cmd.Context(), appID, host)
			if err != nil {
				return domainModeError(cmd, err)
			}
			dns, _ := out["dns"].(map[string]interface{})
			txtName, _ := dns["txt_name"].(string)
			txtValue, _ := dns["txt_value"].(string)
			target, _ := dns["cname_target"].(string)
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s is claimed. Publish these DNS records:\n\n", host)
			fmt.Fprintf(w, "  %s.  TXT    %q   (proves the name is yours)\n", txtName, txtValue)
			if target != "" {
				fmt.Fprintf(w, "  %s.  CNAME  %s.   (alias mode)\n", host, target)
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, "For direct mode, point the name at the gateway with an A record instead of the")
			fmt.Fprintln(w, "CNAME: direct mode also needs a CAA record on the name itself, and a CAA record")
			fmt.Fprintln(w, "cannot sit beside a CNAME. privasys apps domains list prints the CAA record once")
			fmt.Fprintln(w, "the hostname is in the app's signed policy.")
			fmt.Fprintf(w, "\nThen: privasys apps domains verify %s %s\n", args[0], host)
			return nil
		},
	}
}

func newAppsDomainsVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <app> <hostname>",
		Short: "Check a claimed hostname's TXT proof now",
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
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			host := normaliseDomainArg(args[1])
			id, err := domainClaimID(cmd, client, appID, host)
			if err != nil {
				return err
			}
			out, err := client.VerifyAppDomain(cmd.Context(), appID, id)
			if err != nil {
				return domainModeError(cmd, err)
			}
			status, _ := out["status"].(string)
			if status == "live" {
				fmt.Fprintf(cmd.OutOrStdout(), "%s is proven and live\n", host)
				return nil
			}
			msg, _ := out["error"].(string)
			if msg == "" {
				msg = "the TXT record was not found yet; DNS changes can take a few minutes"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is %s: %s\n", host, status, msg)
			return nil
		},
	}
}

func newAppsDomainsRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <app> <hostname>",
		Short: "Release a claimed hostname; the app stops answering on it",
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
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			host := normaliseDomainArg(args[1])
			id, err := domainClaimID(cmd, client, appID, host)
			if err != nil {
				return err
			}
			if err := client.DeleteAppDomain(cmd.Context(), appID, id); err != nil {
				return domainModeError(cmd, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is released. If it was in the app's signed policy, approve a policy without it:\n", host)
			fmt.Fprintf(cmd.OutOrStdout(), "  privasys apps policy approve %s --domains <the rest>  (or --clear-domains)\n", args[0])
			return nil
		},
	}
}

func normaliseDomainArg(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// domainClaimID finds the id of an app's claim on host.
func domainClaimID(cmd *cobra.Command, client *api.Client, appID, host string) (string, error) {
	out, err := client.ListAppDomains(cmd.Context(), appID)
	if err != nil {
		return "", err
	}
	return claimIDFrom(out, host)
}

func claimIDFrom(list map[string]interface{}, host string) (string, error) {
	domains, _ := list["domains"].([]interface{})
	for _, d := range domains {
		m, _ := d.(map[string]interface{})
		if h, _ := m["hostname"].(string); strings.EqualFold(h, host) {
			if id, _ := m["id"].(string); id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("the app has no claim on %s (see privasys apps domains list)", host)
}
