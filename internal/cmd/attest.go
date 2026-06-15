// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/ratls"
)

const defaultAttServer = "https://as.privasys.org/verify"

func newAttestCmd() *cobra.Command {
	var challenge, outDir string
	var verify, showExt bool
	var direct, noChallenge bool
	var host, attServer, mrenclave, mrtd string
	cmd := &cobra.Command{
		Use:   "attest <app-id>",
		Short: "Fetch, verify, and export an app's attestation (RA-TLS quote + measurements)",
		Long: `Retrieves the deployed app's attestation: TEE quote (type, MRENCLAVE/MRTD,
RTMRs), the RA-TLS certificate, and the Privasys OID extensions.

By default this asks the management service for the attestation. With --direct
the CLI connects to the enclave itself over RA-TLS, challenges it with a fresh
nonce, and verifies the quote against the attestation server — so it trusts the
enclave's hardware attestation, not the control plane. (Challenge mode requires
a CLI built with the Privasys Go fork.)

  --direct      verify client-side: connect to the enclave and challenge it
  --host        enclave gateway FQDN for --direct (default: resolved from the app)
  --no-challenge use deterministic mode instead of a fresh challenge (--direct)
  --att-server  attestation server verify endpoint (--direct)
  --mrenclave / --mrtd  pin an expected measurement (hex)
  --challenge   request a fresh challenge-response quote (server-side path)
  --verify      submit the quote to the attestation server and show the verdict
  --extensions  print the certificate's OID extensions
  --out <dir>   dump all artifacts`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if direct {
				return runDirectAttest(cmd, env, args[0], host, attServer, mrenclave, mrtd, !noChallenge, outDir)
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			res, err := client.Attest(cmd.Context(), args[0], challenge)
			if err != nil {
				return err
			}

			var verifyRes map[string]interface{}
			if verify {
				verifyRes, err = verifyAttestation(cmd.Context(), client, res)
				if err != nil {
					return err
				}
			}

			if outDir != "" {
				if err := dumpAttestation(outDir, res, verifyRes); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Wrote attestation artifacts to %s\n", outDir)
			}

			// JSON/YAML: emit the full result (plus verify verdict when present).
			if env.Format == "json" || env.Format == "yaml" {
				if verifyRes != nil {
					res["verification"] = verifyRes
				}
				return output.Emit(env.Format, res, nil)
			}

			// Human: summary table, then optional extensions/verify sections.
			if err := output.Emit(env.Format, res, func() output.Table { return attestTable(res) }); err != nil {
				return err
			}
			if showExt {
				fmt.Println()
				_ = output.Emit("table", nil, func() output.Table { return extensionsTable(res) })
			}
			if verifyRes != nil {
				fmt.Println()
				_ = output.Emit("table", nil, func() output.Table { return verifyTable(verifyRes) })
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&challenge, "challenge", "", "challenge nonce for a fresh challenge-response quote (server-side path)")
	cmd.Flags().BoolVar(&verify, "verify", false, "verify the quote with the attestation server (server-side path)")
	cmd.Flags().BoolVar(&showExt, "extensions", false, "print the certificate's OID extensions")
	cmd.Flags().StringVar(&outDir, "out", "", "directory to dump all attestation artifacts into")
	cmd.Flags().BoolVar(&direct, "direct", false, "verify client-side: connect to the enclave and challenge it")
	cmd.Flags().BoolVar(&noChallenge, "no-challenge", false, "with --direct, use deterministic mode instead of a fresh challenge")
	cmd.Flags().StringVar(&host, "host", "", "with --direct, the enclave gateway FQDN (default: resolved from the app)")
	cmd.Flags().StringVar(&attServer, "att-server", defaultAttServer, "with --direct, the attestation server verify endpoint")
	cmd.Flags().StringVar(&mrenclave, "mrenclave", "", "pin an expected MRENCLAVE (hex)")
	cmd.Flags().StringVar(&mrtd, "mrtd", "", "pin an expected MRTD (hex)")
	return cmd
}

// runDirectAttest performs client-side RA-TLS: connect to the enclave, optionally
// challenge it with a fresh nonce, and verify the quote against the attestation
// server — independent of the management service.
func runDirectAttest(cmd *cobra.Command, env *Env, appID, host, attServer, mrenclave, mrtd string, challenge bool, outDir string) error {
	ctx := cmd.Context()

	// Resolve the enclave gateway hostname. --host fully bypasses the control
	// plane; otherwise we read the app's hostname (discovery only — the
	// verification itself is still client-side and independent).
	serverName := host
	if serverName == "" {
		client, err := apiClient(cmd, env)
		if err != nil {
			return err
		}
		app, err := client.GetApp(ctx, appID)
		if err != nil {
			return err
		}
		serverName = output.Str(app, "hostname")
		if serverName == "" {
			return fmt.Errorf("could not resolve the app's hostname; pass --host <enclave-fqdn>")
		}
	}

	// Best-effort attestation-server token (aud=attestation-server).
	attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")

	var nonce []byte
	if challenge {
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
	}
	if !res.Verified {
		return fmt.Errorf("attestation NOT verified: %s", res.VerifyError)
	}
	return nil
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
	for _, o := range r.CustomOIDs {
		rows = append(rows, []string{o.Label, o.ValueHex})
	}
	rows = append(rows, []string{"VERIFIED", fmt.Sprintf("%t", r.Verified)})
	if r.VerifyError != "" {
		rows = append(rows, []string{"error", r.VerifyError})
	}
	return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
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

func quoteOf(res map[string]interface{}) map[string]interface{} {
	if q, ok := res["quote"].(map[string]interface{}); ok {
		return q
	}
	return nil
}

func verifyAttestation(ctx context.Context, client *api.Client, res map[string]interface{}) (map[string]interface{}, error) {
	q := quoteOf(res)
	raw := ""
	if q != nil {
		raw = output.Str(q, "raw_base64")
	}
	if raw == "" {
		return nil, fmt.Errorf("no raw quote available to verify (the app may be SGX-mock or undeployed)")
	}
	return client.VerifyQuote(ctx, raw)
}

func attestTable(res map[string]interface{}) output.Table {
	rows := [][]string{}
	if q := quoteOf(res); q != nil {
		rows = append(rows, []string{"quote type", output.Str(q, "type")})
		for _, f := range []struct{ key, label string }{
			{"mr_enclave", "mr_enclave"}, {"mr_signer", "mr_signer"}, {"mr_td", "mr_td"},
			{"rtmr0", "rtmr0"}, {"rtmr1", "rtmr1"}, {"rtmr2", "rtmr2"}, {"rtmr3", "rtmr3"},
			{"report_data", "report_data"},
		} {
			if v := output.Str(q, f.key); v != "" {
				rows = append(rows, []string{f.label, v})
			}
		}
	}
	if v := output.Str(res, "cwasm_hash"); v != "" {
		rows = append(rows, []string{"cwasm_hash", v})
	}
	rows = append(rows, []string{"challenge_mode", output.Str(res, "challenge_mode")})
	if len(rows) == 0 {
		rows = append(rows, []string{"result", "see --format json for the full attestation"})
	}
	return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

func extensionsTable(res map[string]interface{}) output.Table {
	rows := [][]string{}
	collect := func(key string) {
		if list, ok := res[key].([]interface{}); ok {
			for _, e := range list {
				em, ok := e.(map[string]interface{})
				if !ok {
					continue
				}
				rows = append(rows, []string{output.Str(em, "oid"), output.Str(em, "label"), output.Str(em, "value_hex")})
			}
		}
	}
	collect("extensions")
	collect("app_extensions")
	if len(rows) == 0 {
		rows = append(rows, []string{"(none)", "", ""})
	}
	return output.Table{Headers: []string{"OID", "LABEL", "VALUE (hex)"}, Rows: rows}
}

func verifyTable(v map[string]interface{}) output.Table {
	return output.Table{
		Headers: []string{"VERIFICATION", "VALUE"},
		Rows: [][]string{
			{"success", output.Str(v, "success")},
			{"status", output.Str(v, "status")},
			{"tee_type", output.Str(v, "teeType")},
			{"mrenclave", output.Str(v, "mrenclave")},
			{"mrtd", output.Str(v, "mrtd")},
			{"message", output.Str(v, "message") + output.Str(v, "error")},
		},
	}
}

// dumpAttestation writes the attestation artifacts to dir.
func dumpAttestation(dir string, res, verifyRes map[string]interface{}) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	writeJSON := func(name string, v interface{}) error {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	if err := writeJSON("attestation.json", res); err != nil {
		return err
	}
	if pem := output.Str(res, "pem"); pem != "" {
		if err := os.WriteFile(filepath.Join(dir, "certificate.pem"), []byte(pem), 0o600); err != nil {
			return err
		}
	}
	if pem := output.Str(res, "app_pem"); pem != "" {
		if err := os.WriteFile(filepath.Join(dir, "app-certificate.pem"), []byte(pem), 0o600); err != nil {
			return err
		}
	}
	if q := quoteOf(res); q != nil {
		if raw := output.Str(q, "raw_base64"); raw != "" {
			if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
				if err := os.WriteFile(filepath.Join(dir, "quote.bin"), b, 0o600); err != nil {
					return err
				}
			}
		}
	}
	if exts, ok := res["extensions"]; ok {
		if err := writeJSON("extensions.json", exts); err != nil {
			return err
		}
	}
	if verifyRes != nil {
		if err := writeJSON("verify.json", verifyRes); err != nil {
			return err
		}
	}
	return nil
}
