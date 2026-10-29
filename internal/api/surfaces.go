// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// SurfacesConfirmationRequired is the platform's error code when a deploy or
// stage would ship routes served in the clear that no owner has confirmed yet.
const SurfacesConfirmationRequired = "surfaces_confirmation_required"

// SurfacesRefusal is the body of that refusal: every route the version serves
// in the clear, and those new since the last confirmation.
type SurfacesRefusal struct {
	Message string   `json:"message"`
	Entries []string `json:"entries"`
	Added   []string `json:"added"`
}

// AsSurfacesRefusal reports whether err is the platform asking for an owner's
// confirmation of a version's clear routes, and what it asks about.
func AsSurfacesRefusal(err error) (*SurfacesRefusal, bool) {
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusConflict || se.Code() != SurfacesConfirmationRequired {
		return nil, false
	}
	var body SurfacesRefusal
	if se.Decode(&body) != nil {
		return nil, false
	}
	return &body, true
}

// VersionSurfaceEntries names the routes a version serves in the clear, as
// the platform lists them ("static /assets/", "GET /api/v1/public/x"), so a
// confirmation built from them matches the platform's own list.
func VersionSurfaceEntries(v map[string]interface{}) []string {
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
			method, _ := r["method"].(string)
			path, _ := r["path"].(string)
			entries = append(entries, strings.ToUpper(strings.TrimSpace(method))+" "+strings.TrimSpace(path))
		}
	}
	return entries
}
