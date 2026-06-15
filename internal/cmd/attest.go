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
	"github.com/Privasys/cli/internal/output"
)

func newAttestCmd() *cobra.Command {
	var challenge, outDir string
	var verify, showExt bool
	cmd := &cobra.Command{
		Use:   "attest <app-id>",
		Short: "Fetch, verify, and export an app's attestation (RA-TLS quote + measurements)",
		Long: `Retrieves the deployed app's attestation: TEE quote (type, MRENCLAVE/MRTD,
RTMRs), the RA-TLS certificate, and the Privasys OID extensions.

  --challenge   request a fresh challenge-response quote (not the cached cert)
  --verify      submit the quote to the attestation server and show the verdict
  --extensions  print the certificate's OID extensions
  --out <dir>   dump all artifacts: attestation.json, certificate.pem,
                app-certificate.pem, quote.bin, extensions.json, verify.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
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
	cmd.Flags().StringVar(&challenge, "challenge", "", "challenge nonce for a fresh challenge-response quote")
	cmd.Flags().BoolVar(&verify, "verify", false, "verify the quote with the attestation server")
	cmd.Flags().BoolVar(&showExt, "extensions", false, "print the certificate's OID extensions")
	cmd.Flags().StringVar(&outDir, "out", "", "directory to dump all attestation artifacts into")
	return cmd
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
