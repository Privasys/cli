// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/oci"
	"github.com/Privasys/cli/internal/output"
)

// manifestLabel is the OCI label that carries an app's privasys.json.
const manifestLabel = "org.privasys.manifest"

// imageHostFlagDesc describes --image-host, shared by the commands that read a
// private image with the owner's credential.
const imageHostFlagDesc = "the registry host you expect the app's image on, e.g. ghcr.io: the credential goes nowhere else, and you are not asked"

// approveImageHost gets the owner's agreement before their pull credential goes
// to the app's registry. The image reference comes from the control plane,
// which never holds the credential and must not be able to obtain it by naming
// another host, so the owner states the host (--image-host) or approves it here.
func approveImageHost(cmd *cobra.Command, env *Env, image, imageHost string) error {
	ref, err := oci.ParseRef(image)
	if err != nil {
		return err
	}
	if imageHost != "" {
		want, err := oci.ParseRef(imageHost + "/app")
		if err != nil {
			return fmt.Errorf("--image-host: %w", err)
		}
		if !strings.EqualFold(want.Registry, ref.Registry) {
			return fmt.Errorf("the platform names the app's image %s, on %s and not %s: the credential was not sent", image, ref.Registry, imageHost)
		}
		return nil
	}
	if env.NoInput || !stdoutIsTTY() {
		return fmt.Errorf("the platform names the app's image %s: pass --image-host %s to send the credential to that registry", image, ref.Registry)
	}
	ok, err := confirm(cmd, env, fmt.Sprintf("Send your pull credential to %s to read the manifest of %s?", ref.Registry, image))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the credential was not sent to %s", ref.Registry)
	}
	return nil
}

// recordManifestFromImage reads the app manifest off the app's pinned private
// image with the given pull credential and records it on the app through the
// owner API. The control plane reads image labels anonymously by design and so
// never sees the manifest of a private image: without this step a private
// package app has no tools and no configure section in the portal, the CLI or
// the MCP tools. Each version's surfaces are unaffected: the control plane
// records those when it creates the version.
//
// It returns (false, nil) when the app is not a package app or the image
// carries no manifest label.
func recordManifestFromImage(cmd *cobra.Command, env *Env, client *api.Client, appID, username, password, imageHost string) (bool, error) {
	ctx := cmd.Context()
	app, err := client.GetApp(ctx, appID)
	if err != nil {
		return false, err
	}
	image, _ := app["container_image"].(string)
	if source, _ := app["source_type"].(string); image == "" || (source != "" && source != "package") {
		return false, nil
	}
	if err := approveImageHost(cmd, env, image, imageHost); err != nil {
		return false, err
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
	if !env.Quiet {
		var m struct {
			Tools []json.RawMessage `json:"tools"`
		}
		_ = json.Unmarshal(raw, &m)
		output.Success(cmd.ErrOrStderr(), "Recorded the app manifest from the private image (%d tools)", len(m.Tools))
	}
	return true, nil
}
