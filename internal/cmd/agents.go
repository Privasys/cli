// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/agents"
	"github.com/Privasys/cli/internal/output"
)

func newAgentsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "agents",
		Short: "Wire the Privasys MCP server into AI-agent harnesses",
		Long:  "Generate the MCP registration that lets an AI agent drive the platform. Everything points at the local privasys binary, which reads its token from the OS keychain, so no secret is ever written to disk.",
	}
	c.AddCommand(newAgentsInitCmd())
	return c
}

func newAgentsInitCmd() *cobra.Command {
	var (
		harnesses  []string
		all        bool
		dir        string
		printOnly  bool
		noAgentsMD bool
	)
	c := &cobra.Command{
		Use:   "init",
		Short: "Write MCP registration + AGENTS.md so an agent can mount the platform",
		Long: "Drops a project-local MCP registration for the chosen harness(es) and an AGENTS.md briefing, so an AI agent picks up the privasys tools with no manual JSON editing.\n\n" +
			"Defaults to Claude Code. Use --harness (repeatable) to pick others or --all for every known harness:\n  " +
			strings.Join(agents.Names(), ", ") + "\n\n" +
			"Re-running is idempotent: existing servers and unrelated keys are preserved, and the AGENTS.md block is replaced in place.",
		Example: "  privasys agents init                 # Claude Code + AGENTS.md in the current repo\n" +
			"  privasys agents init --all          # every supported harness\n" +
			"  privasys agents init --harness cursor --harness vscode\n" +
			"  privasys agents init --print        # show what would be written, touch nothing",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}

			selected, err := resolveHarnesses(harnesses, all)
			if err != nil {
				return err
			}

			type result struct {
				Harness string `json:"harness,omitempty"`
				Path    string `json:"path"`
				Status  string `json:"status"`
			}
			var results []result

			for _, h := range selected {
				path := filepath.Join(dir, filepath.FromSlash(h.Path))
				existing, _ := os.ReadFile(path)
				merged, changed, err := h.Merge(existing)
				if err != nil {
					return err
				}
				if printOnly {
					fmt.Fprintf(cmd.OutOrStdout(), "# %s -> %s\n%s\n", h.Title, h.Path, merged)
					results = append(results, result{Harness: h.Name, Path: h.Path, Status: "preview"})
					continue
				}
				status, err := writeFile(path, merged, len(existing) > 0, changed)
				if err != nil {
					return err
				}
				results = append(results, result{Harness: h.Name, Path: h.Path, Status: status})
			}

			if !noAgentsMD {
				path := filepath.Join(dir, "AGENTS.md")
				existing, _ := os.ReadFile(path)
				merged, changed := agents.MergeAgentsMD(existing)
				if printOnly {
					fmt.Fprintf(cmd.OutOrStdout(), "# AGENTS.md\n%s\n", merged)
					results = append(results, result{Path: "AGENTS.md", Status: "preview"})
				} else {
					status, err := writeFile(path, merged, len(existing) > 0, changed)
					if err != nil {
						return err
					}
					results = append(results, result{Path: "AGENTS.md", Status: status})
				}
			}

			if env.Format == "json" || env.Format == "yaml" {
				return output.Emit(env.Format, results, nil)
			}
			if printOnly {
				return nil
			}
			for _, r := range results {
				output.Success(cmd.ErrOrStderr(), "%s %s", r.Status, r.Path)
			}
			if !env.Quiet {
				fmt.Fprintf(cmd.ErrOrStderr(), "\n%s Next: start your agent here, or run %s to verify the wiring.\n",
					output.Check(), output.Bold("privasys mcp serve"))
			}
			return nil
		},
	}
	c.Flags().StringArrayVar(&harnesses, "harness", nil, "harness to wire (repeatable): "+strings.Join(agents.Names(), ", "))
	c.Flags().BoolVar(&all, "all", false, "wire every supported harness")
	c.Flags().StringVar(&dir, "dir", ".", "project directory to write into")
	c.Flags().BoolVar(&printOnly, "print", false, "print what would be written without touching disk")
	c.Flags().BoolVar(&noAgentsMD, "no-agents-md", false, "do not write/update AGENTS.md")
	return c
}

// resolveHarnesses turns the flags into the concrete set, defaulting to Claude
// Code when nothing is asked for.
func resolveHarnesses(names []string, all bool) ([]agents.Harness, error) {
	if all {
		return agents.All(), nil
	}
	if len(names) == 0 {
		h, _ := agents.Lookup("claude")
		return []agents.Harness{h}, nil
	}
	var out []agents.Harness
	var unknown []string
	for _, n := range names {
		if h, ok := agents.Lookup(strings.ToLower(strings.TrimSpace(n))); ok {
			out = append(out, h)
		} else {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown harness(es): %s (known: %s)", strings.Join(unknown, ", "), strings.Join(agents.Names(), ", "))
	}
	return out, nil
}

// writeFile creates parent dirs and writes content, returning a human status
// describing what happened so the summary is honest about no-ops.
func writeFile(path string, content []byte, existed, changed bool) (string, error) {
	if existed && !changed {
		return "unchanged", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", err
	}
	if existed {
		return "updated", nil
	}
	return "created", nil
}
