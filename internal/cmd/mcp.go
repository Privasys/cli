// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/mcp"
)

func newMcpCmd() *cobra.Command {
	c := &cobra.Command{Use: "mcp", Short: "Model Context Protocol server"}
	c.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Serve the platform as MCP tools over stdio (for AI agents)",
		Long:  "Exposes the CLI's full command surface as MCP tools over newline-delimited JSON-RPC on stdio. Authenticates with the current session or a service account, exactly like the CLI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			// Rebuild an authenticated client per call so tokens refresh.
			deps := func(ctx context.Context) (mcp.Deps, error) {
				token, err := auth.AccessToken(ctx, env.Cfg.Issuer)
				if err != nil {
					return mcp.Deps{}, err
				}
				return mcp.Deps{Client: api.New(env.Cfg.Endpoint, token), Token: token, Issuer: env.Cfg.Issuer}, nil
			}
			srv := mcp.NewServer(deps, resolveVersion())
			return srv.Serve(cmd.Context(), os.Stdin, os.Stdout)
		},
	})
	return c
}
