// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/oci"
	"github.com/Privasys/cli/internal/output"
)

// manifestLabel is the OCI label that carries an app's privasys.json.
const manifestLabel = "org.privasys.manifest"

// recordManifestFromImage reads the app manifest off the app's pinned private
// image with the given pull credential and records it on the app through the
// owner API. The control plane reads image labels anonymously by design and so
// never sees the manifest of a private image: without this step a private
// package app has no tools, no configure section and no declared surfaces in
// the portal, the CLI or the MCP tools.
//
// It returns (false, nil) when the app is not a package app or the image
// carries no manifest label.
func recordManifestFromImage(ctx context.Context, w io.Writer, quiet bool, client *api.Client, appID, username, password string) (bool, error) {
	app, err := client.GetApp(ctx, appID)
	if err != nil {
		return false, err
	}
	image, _ := app["container_image"].(string)
	if image == "" {
		return false, nil
	}
	raw, err := oci.NewClient().FetchLabel(ctx, image, manifestLabel, &oci.Credential{Username: username, Password: password})
	if err != nil {
		return false, fmt.Errorf("read %s from %s: %w", manifestLabel, image, err)
	}
	if len(raw) == 0 {
		return false, nil
	}
	if _, err := client.SetMCP(ctx, appID, raw); err != nil {
		return false, fmt.Errorf("record manifest: %w", err)
	}
	if !quiet {
		var m struct {
			Tools []json.RawMessage `json:"tools"`
		}
		_ = json.Unmarshal(raw, &m)
		output.Success(w, "Recorded the app manifest from the private image (%d tools)", len(m.Tools))
	}
	return true, nil
}
