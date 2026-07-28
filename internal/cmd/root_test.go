// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/config"
)

// TestEndpointResolution locks the endpoint precedence:
// --endpoint (custom) > --test (dev preset) > config/env > default (production).
func TestEndpointResolution(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows home
	t.Setenv("PRIVASYS_ENDPOINT", "")

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default is production", nil, config.DefaultEndpoint},
		{"--test selects the dev environment", []string{"--test"}, config.TestEndpoint},
		{"--endpoint sets a custom environment", []string{"--endpoint", "https://custom.example"}, "https://custom.example"},
		{"--endpoint overrides --test", []string{"--test", "--endpoint", "https://custom.example"}, "https://custom.example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got string
			root := NewRoot()
			probe := &cobra.Command{Use: "probe", RunE: func(cmd *cobra.Command, _ []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				got = env.Cfg.Endpoint
				return nil
			}}
			root.AddCommand(probe)
			root.SetArgs(append(append([]string{}, c.args...), "probe"))
			if err := root.Execute(); err != nil {
				t.Fatalf("execute %v: %v", c.args, err)
			}
			if got != c.want {
				t.Errorf("args %v: endpoint = %q, want %q", c.args, got, c.want)
			}
		})
	}
}
