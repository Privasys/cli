// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"errors"

	"github.com/Privasys/cli/internal/api"
)

// Surfaces: routes a container app serves in the CLEAR through the platform
// gateway (its static shell and public routes). The platform refuses to deploy
// or stage a version that adds one until an OWNER confirms those routes carry
// no personal data, and records who confirmed with the version. That is a
// human judgement about the app's data, so the tools are two-phase like the
// upgrade: the refusal comes back as the routes to review, and only a second
// call with confirm_surfaces:true records the owner's answer and ships.

const confirmSurfacesDesc = "the app owner reviewed the routes this version serves in the clear (returned by a first call) and confirmed they carry no personal data; records that confirmation and ships"

// surfacesReview is returned (as an error, so it unwinds through the staging
// and deploy helpers) when the platform asks for that confirmation and the
// caller has not given it. withSurfacesReview turns it into the tool result.
type surfacesReview struct {
	appID, versionID string
	refusal          *api.SurfacesRefusal
}

func (e *surfacesReview) Error() string { return e.refusal.Message }

// shipSurfaces runs ship; on the platform's surfaces refusal it records the
// owner's confirmation and retries when the caller passed confirm_surfaces,
// and otherwise stops with a surfacesReview.
func shipSurfaces(ctx context.Context, d Deps, args map[string]interface{}, appID, versionID string,
	ship func() (map[string]interface{}, error)) (map[string]interface{}, error) {
	res, err := ship()
	if err == nil {
		return res, nil
	}
	refusal, ok := api.AsSurfacesRefusal(err)
	if !ok {
		return nil, err
	}
	if confirmed, _ := args["confirm_surfaces"].(bool); !confirmed {
		return nil, &surfacesReview{appID: appID, versionID: versionID, refusal: refusal}
	}
	if _, err := d.Client.ConfirmSurfaces(ctx, appID, versionID, refusal.Entries); err != nil {
		return nil, err
	}
	return ship()
}

// withSurfacesReview wraps a shipping tool's handler: a surfacesReview becomes
// a structured "not shipped, ask the owner" result rather than an error.
func withSurfacesReview(h func(context.Context, Deps, map[string]interface{}) (interface{}, error)) func(context.Context, Deps, map[string]interface{}) (interface{}, error) {
	return func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
		res, err := h(ctx, d, args)
		var rv *surfacesReview
		if errors.As(err, &rv) {
			return surfacesReviewResult(rv), nil
		}
		return res, err
	}
}

func surfacesReviewResult(rv *surfacesReview) map[string]interface{} {
	added := rv.refusal.Added
	if added == nil {
		added = []string{}
	}
	return map[string]interface{}{
		"shipped":                        false,
		"surfaces_confirmation_required": true,
		"version":                        rv.versionID,
		"routes_in_clear":                rv.refusal.Entries,
		"new_since_last_confirmation":    added,
		"message":                        rv.refusal.Message,
		"next": "Nothing was shipped. This version serves 'routes_in_clear' through the platform gateway, which reads that traffic; " +
			"everything else stays sealed end to end. Show the routes (the new ones especially) to the app owner and ask them to confirm " +
			"these routes carry no personal data. Only if they say yes, call this tool again with the same arguments plus confirm_surfaces:true; " +
			"the confirmation is recorded with the version under their account. Never confirm on their behalf.",
	}
}
