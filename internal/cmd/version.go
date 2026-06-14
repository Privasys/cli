// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

// resolveVersion prefers the ldflags-stamped Version, falling back to the
// module version embedded by `go install module@version` so users can always
// tell which build they are running.
func resolveVersion() string {
	if Version != "dev" && Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return Version
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the CLI version",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ver := resolveVersion()
			info := map[string]string{"version": ver, "commit": Commit, "built": Date}
			return output.Emit(env.Format, info, func() output.Table {
				return output.Table{Rows: [][]string{{fmt.Sprintf("privasys %s (commit %s, built %s)", ver, Commit, Date)}}}
			})
		},
	}
}
