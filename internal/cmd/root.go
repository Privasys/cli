// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package cmd builds the privasys CLI command tree.
package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/config"
)

// Build version, injected via -ldflags at release time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Env is the resolved per-invocation context: the active configuration with
// flag/env overrides applied.
type Env struct {
	File    *config.File
	Cfg     *config.Configuration
	Format  string
	NoInput bool
	Quiet   bool
}

// NewRoot builds the root command.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "privasys",
		Short:         "Privasys platform CLI — deploy and manage confidential apps",
		Long:          "privasys is the command-line interface to the Privasys confidential-computing platform: authenticate with the wallet, deploy apps, manage teams and billing, and verify attestation. Designed for developers, CI, and AI agents.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String("format", "", "output format: table|json|yaml")
	root.PersistentFlags().String("endpoint", "", "platform API base URL")
	root.PersistentFlags().String("issuer", "", "identity provider issuer URL")
	root.PersistentFlags().String("account", "", "account id to act on")
	root.PersistentFlags().Bool("no-input", false, "never prompt; fail instead")
	root.PersistentFlags().BoolP("quiet", "q", false, "suppress non-essential output")

	root.AddCommand(
		newAuthCmd(),
		newConfigCmd(),
		newAppsCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI.
func Execute() {
	if err := NewRoot().Execute(); err != nil {
		// Cobra already printed nothing (SilenceErrors); print to stderr.
		os.Stderr.WriteString("error: " + err.Error() + "\n")
		os.Exit(1)
	}
}

// loadEnv resolves the configuration with persistent-flag and env overrides.
func loadEnv(cmd *cobra.Command) (*Env, error) {
	f, err := config.Load()
	if err != nil {
		return nil, err
	}
	cfg := f.Active() // applies PRIVASYS_* env overrides

	if v, _ := cmd.Flags().GetString("endpoint"); v != "" {
		cfg.Endpoint = v
	}
	if v, _ := cmd.Flags().GetString("issuer"); v != "" {
		cfg.Issuer = v
	}
	if v, _ := cmd.Flags().GetString("account"); v != "" {
		cfg.Account = v
	}
	format := cfg.Format
	if v, _ := cmd.Flags().GetString("format"); v != "" {
		format = v
	}
	noInput, _ := cmd.Flags().GetBool("no-input")
	quiet, _ := cmd.Flags().GetBool("quiet")

	return &Env{File: f, Cfg: cfg, Format: format, NoInput: noInput, Quiet: quiet}, nil
}
