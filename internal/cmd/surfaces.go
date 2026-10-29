package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/output"
)

// Surfaces: the routes a container app declared it serves in the CLEAR on
// the gateway-terminated leg (its static browser shell and its public
// routes). Everything else is sealed end to end. The platform refuses to
// deploy or stage a version that adds such a route until an owner confirms
// those routes carry no personal data; the confirmation is recorded with the
// version. These helpers show the routes and take that confirmation.

// The refusal itself (api.AsSurfacesRefusal) is shared with the MCP tools.

// withSurfacesConfirmation runs ship once; when the platform answers that the
// version serves new routes in the clear, it shows them, asks the owner (or
// takes --confirm-surfaces as the answer), records the confirmation and runs
// ship again.
func withSurfacesConfirmation(cmd *cobra.Command, env *Env, client *api.Client, appID, vid string, preConfirmed bool,
	ship func() (map[string]interface{}, error)) (map[string]interface{}, error) {
	res, err := ship()
	if err == nil {
		return res, nil
	}
	refusal, ok := api.AsSurfacesRefusal(err)
	if !ok {
		return nil, err
	}
	printSurfaces(cmd, refusal)
	if !preConfirmed {
		yes, cerr := confirm(cmd, env, "Confirm these routes carry no personal data?")
		if cerr != nil {
			return nil, fmt.Errorf("%w (or pass --confirm-surfaces)", cerr)
		}
		if !yes {
			return nil, fmt.Errorf("not confirmed; the version was not shipped")
		}
	}
	if _, err := client.ConfirmSurfaces(cmd.Context(), appID, vid, refusal.Entries); err != nil {
		return nil, err
	}
	if !env.Quiet {
		fmt.Fprintln(cmd.ErrOrStderr(), "✓ surfaces confirmed")
	}
	return ship()
}

func printSurfaces(cmd *cobra.Command, r *api.SurfacesRefusal) {
	w := cmd.ErrOrStderr()
	added := map[string]bool{}
	for _, e := range r.Added {
		added[e] = true
	}
	fmt.Fprintf(w, "This version serves %d routes in the clear (%d new since the last confirmation).\n", len(r.Entries), len(r.Added))
	fmt.Fprintln(w, "The platform gateway reads traffic on these routes; the enclave serves them anonymously.")
	for _, e := range r.Entries {
		if added[e] {
			fmt.Fprintf(w, "  %s  (new)\n", e)
		} else {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

// surfacesSummary renders an app's declaration from its manifest for `apps
// describe`: "static /, /assets/; GET /api/v1/public/, POST /api/v1/webhooks/x".
func surfacesSummary(app map[string]interface{}) string {
	mcp, _ := app["container_mcp"].(map[string]interface{})
	surf, _ := mcp["surfaces"].(map[string]interface{})
	if surf == nil {
		return ""
	}
	var parts []string
	if st, ok := surf["static"].([]interface{}); ok && len(st) > 0 {
		ss := make([]string, 0, len(st))
		for _, p := range st {
			ss = append(ss, fmt.Sprint(p))
		}
		parts = append(parts, "static "+strings.Join(ss, ", "))
	}
	if pub, ok := surf["public"].([]interface{}); ok {
		for _, p := range pub {
			r, _ := p.(map[string]interface{})
			if r == nil {
				continue
			}
			parts = append(parts, strings.ToUpper(output.Str(r, "method"))+" "+output.Str(r, "path"))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

func newVersionsConfirmSurfacesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "confirm-surfaces <app> [version]",
		Short: "Confirm that the routes a version serves in the clear carry no personal data (owner-only)",
		Long: "A container app declares in its manifest which routes it serves in the clear through the platform gateway " +
			"(its static browser shell and its public routes). A version that adds such a route is not deployed or staged " +
			"until an owner confirms those routes carry no personal data. `apps deploy` and `apps versions stage` ask for it; " +
			"this command records it ahead of time. The confirmation (who, when, which routes) stays with the version.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			vid, err := resolveVersionRef(cmd.Context(), client, appID, argOr(args, 1, ""))
			if err != nil {
				return err
			}
			v, err := client.GetVersion(cmd.Context(), appID, vid)
			if err != nil {
				return err
			}
			entries := api.VersionSurfaceEntries(v)
			if len(entries) == 0 {
				return fmt.Errorf("this version serves nothing in the clear; there is nothing to confirm")
			}
			printSurfaces(cmd, &api.SurfacesRefusal{Entries: entries})
			yes, err := confirm(cmd, env, "Confirm these routes carry no personal data?")
			if err != nil {
				return err
			}
			if !yes {
				return fmt.Errorf("not confirmed")
			}
			res, err := client.ConfirmSurfaces(cmd.Context(), appID, vid, entries)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				return kvTable(res, []string{"id", "version_number", "surfaces_confirmed_by", "surfaces_confirmed_at"})
			})
		},
	}
}
