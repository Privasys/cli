// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/ratls"
)

const defaultAttServer = "https://as.privasys.org/verify"

// newAttestCmd builds `attest`, which is always client-side: the CLI connects
// to the enclave over RA-TLS, challenges it with a fresh nonce, and verifies
// the quote against the attestation server. There is no control-plane path —
// attestation is the client's job, not something to be told by a proxy.
func newAttestCmd() *cobra.Command {
	var outDir, host, attServer, mrenclave, mrtd string
	var noChallenge, showExt bool
	cmd := &cobra.Command{
		Use:   "attest <app-id>",
		Short: "Verify an app's enclave client-side (RA-TLS challenge + quote verification)",
		Long: `Connects to the app's enclave over RA-TLS (through the gateway's L4 splice),
challenges it with a fresh nonce, and verifies the quote against the attestation
server. The CLI trusts the enclave's hardware attestation, never the control
plane. Challenge mode requires a CLI built with the Privasys Go fork.

  --host         enclave gateway FQDN (default: resolved from the app)
  --no-challenge use deterministic mode instead of a fresh challenge
  --att-server   attestation server verify endpoint
  --mrenclave / --mrtd  pin an expected measurement (hex)
  --extensions   print the certificate's OID extensions
  --out <dir>    dump artifacts: attestation.json, certificate.pem, quote.bin`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			// Resolve the enclave gateway hostname. --host bypasses the control
			// plane entirely; otherwise we read the app's hostname from the
			// registry (metadata only — the verification is still client-side).
			serverName := host
			if serverName == "" {
				client, err := apiClient(cmd, env)
				if err != nil {
					return err
				}
				appID, err := resolveAppID(ctx, client, args[0])
				if err != nil {
					return err
				}
				serverName, err = client.ActiveDeploymentHost(ctx, appID)
				if err != nil {
					return fmt.Errorf("%w; pass --host <enclave-fqdn>", err)
				}
			}

			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")
			var nonce []byte
			if !noChallenge {
				nonce = ratls.NewNonce()
			}
			res, err := ratls.Verify(ctx, ratls.Params{
				Host: serverName, Port: 443, ServerName: serverName,
				Challenge: nonce, AttServerURL: attServer, AttServerTok: attTok,
				ExpectMRENCLA: mrenclave, ExpectMRTD: mrtd,
			})
			if err != nil {
				return err
			}

			if outDir != "" {
				if err := dumpDirect(outDir, res); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Wrote attestation artifacts to %s\n", outDir)
			}

			if env.Format == "json" || env.Format == "yaml" {
				if err := output.Emit(env.Format, res, nil); err != nil {
					return err
				}
			} else {
				_ = output.Emit("table", nil, func() output.Table { return directTable(res) })
				if showExt && len(res.CustomOIDs) > 0 {
					fmt.Println()
					_ = output.Emit("table", nil, func() output.Table { return oidTable(res) })
				}
			}
			if !res.Verified {
				return fmt.Errorf("attestation NOT verified: %s", res.VerifyError)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "enclave gateway FQDN (default: resolved from the app)")
	cmd.Flags().BoolVar(&noChallenge, "no-challenge", false, "use deterministic mode instead of a fresh challenge")
	cmd.Flags().StringVar(&attServer, "att-server", defaultAttServer, "attestation server verify endpoint")
	cmd.Flags().StringVar(&mrenclave, "mrenclave", "", "pin an expected MRENCLAVE (hex)")
	cmd.Flags().StringVar(&mrtd, "mrtd", "", "pin an expected MRTD (hex)")
	cmd.Flags().BoolVar(&showExt, "extensions", false, "print the certificate's OID extensions")
	cmd.Flags().StringVar(&outDir, "out", "", "directory to dump attestation artifacts into")
	return cmd
}

func directTable(r *ratls.Result) output.Table {
	rows := [][]string{
		{"host", r.Host},
		{"tls", r.TLSVersion + " " + r.CipherSuite},
		{"quote type", r.QuoteType},
		{"challenged", fmt.Sprintf("%t", r.Challenged)},
		{"pubkey_sha256", r.PubKeySHA256},
	}
	if r.QuoteStatus != "" {
		rows = append(rows, []string{"quote status", r.QuoteStatus})
	}
	rows = append(rows, []string{"VERIFIED", fmt.Sprintf("%t", r.Verified)})
	if r.VerifyError != "" {
		rows = append(rows, []string{"error", r.VerifyError})
	}
	return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

func oidTable(r *ratls.Result) output.Table {
	rows := make([][]string, 0, len(r.CustomOIDs))
	for _, o := range r.CustomOIDs {
		rows = append(rows, []string{o.OID, o.Label, o.ValueHex})
	}
	return output.Table{Headers: []string{"OID", "LABEL", "VALUE (hex)"}, Rows: rows}
}

func dumpDirect(dir string, r *ratls.Result) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "attestation.json"), b, 0o600); err != nil {
		return err
	}
	if r.CertPEM != "" {
		if err := os.WriteFile(filepath.Join(dir, "certificate.pem"), []byte(r.CertPEM), 0o600); err != nil {
			return err
		}
	}
	if len(r.QuoteRaw) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "quote.bin"), r.QuoteRaw, 0o600); err != nil {
			return err
		}
	}
	return nil
}
