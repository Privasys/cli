package cmd

import (
	"errors"
	"fmt"
	"net/http"
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

// surfacesConfirmationRequired is the platform's error code for that refusal.
const surfacesConfirmationRequired = "surfaces_confirmation_required"

// surfacesRefusal is the body of that refusal.
type surfacesRefusal struct {
	Message string   `json:"message"`
	Entries []string `json:"entries"`
	Added   []string `json:"added"`
}

// asSurfacesRefusal reports whether err is the platform asking for an
// owner's confirmation, and what it asks about.
func asSurfacesRefusal(err error) (*surfacesRefusal, bool) {
	var se *api.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusConflict || se.Code() != surfacesConfirmationRequired {
		return nil, false
	}
	var body surfacesRefusal
	if se.Decode(&body) != nil {
		return nil, false
	}
	return &body, true
}

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
	refusal, ok := asSurfacesRefusal(err)
	if !ok {
		return nil, err
	}
	printSurfaces(cmd, refusal)
	if !preConfirmed {
		yes, cerr := confirm(cmd, env, "Confirm these routes carry no personal data, and may be served in the clear?")
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
		fmt.Fprintln(cmd.ErrOrStderr(), "Confirmation recorded on the version.")
	}
	return ship()
}

func printSurfaces(cmd *cobra.Command, r *surfacesRefusal) {
	w := cmd.ErrOrStderr()
	fmt.Fprintln(w, "This version serves routes IN THE CLEAR through the platform gateway, which reads them:")
	added := map[string]bool{}
	for _, e := range r.Added {
		added[e] = true
	}
	for _, e := range r.Entries {
		mark := "  "
		if added[e] {
			mark = "+ "
		}
		fmt.Fprintf(w, "  %s%s\n", mark, e)
	}
	if len(r.Added) > 0 {
		fmt.Fprintln(w, "(+ marks a route no owner has confirmed before.)")
	}
	fmt.Fprintln(w, "The enclave serves them anonymously (no credential reaches the app) and the attestation records them.")
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
			entries := versionSurfaceEntries(v)
			if len(entries) == 0 {
				return fmt.Errorf("this version serves nothing in the clear; there is nothing to confirm")
			}
			printSurfaces(cmd, &surfacesRefusal{Entries: entries})
			yes, err := confirm(cmd, env, "Confirm these routes carry no personal data, and may be served in the clear?")
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

// versionSurfaceEntries lists a version's clear routes exactly as the platform
// names them, so a confirmation matches.
func versionSurfaceEntries(v map[string]interface{}) []string {
	surf, _ := v["surfaces"].(map[string]interface{})
	if surf == nil {
		return nil
	}
	var entries []string
	if st, ok := surf["static"].([]interface{}); ok {
		for _, p := range st {
			entries = append(entries, "static "+strings.TrimSpace(fmt.Sprint(p)))
		}
	}
	if pub, ok := surf["public"].([]interface{}); ok {
		for _, p := range pub {
			r, _ := p.(map[string]interface{})
			if r == nil {
				continue
			}
			entries = append(entries, strings.ToUpper(strings.TrimSpace(output.Str(r, "method")))+" "+strings.TrimSpace(output.Str(r, "path")))
		}
	}
	return entries
}

