// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the CLI version",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			info := map[string]string{"version": Version, "commit": Commit, "built": Date}
			return output.Emit(env.Format, info, func() output.Table {
				return output.Table{Rows: [][]string{{fmt.Sprintf("privasys %s (commit %s, built %s)", Version, Commit, Date)}}}
			})
		},
	}
}
