// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

func newAttestCmd() *cobra.Command {
	var challenge string
	cmd := &cobra.Command{
		Use:   "attest <app-id>",
		Short: "Fetch and show an app's attestation (RA-TLS quote + measurements)",
		Long:  "Retrieves the deployed app's attestation: TEE quote type, measurements (MRENCLAVE/MRTD), and certificate extensions. Pass --challenge for a fresh challenge-response quote rather than the cached certificate.",
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
			res, err := client.Attest(cmd.Context(), args[0], challenge)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				rows := [][]string{}
				if q, ok := res["quote"].(map[string]interface{}); ok {
					rows = append(rows, []string{"quote type", output.Str(q, "type")})
					if v := output.Str(q, "mr_enclave"); v != "" {
						rows = append(rows, []string{"mr_enclave", v})
					}
					if v := output.Str(q, "mr_signer"); v != "" {
						rows = append(rows, []string{"mr_signer", v})
					}
					if v := output.Str(q, "mrtd"); v != "" {
						rows = append(rows, []string{"mrtd", v})
					}
				}
				if v := output.Str(res, "cwasm_hash"); v != "" {
					rows = append(rows, []string{"cwasm_hash", v})
				}
				rows = append(rows, []string{"challenge_mode", output.Str(res, "challenge_mode")})
				if len(rows) == 0 {
					rows = append(rows, []string{"result", "see --format json for full attestation"})
				}
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
			})
		},
	}
	cmd.Flags().StringVar(&challenge, "challenge", "", "challenge nonce for a fresh challenge-response quote")
	return cmd
}
