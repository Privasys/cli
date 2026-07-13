// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/ratls"
	"github.com/Privasys/cli/internal/secrets"
)

// slugifyDisplayName reduces a friendly display name (e.g. "Web Search (Brave)")
// to its canonical app-name form: lowercase, spaces to hyphens, everything else
// dropped. Kept in lockstep with the management-service and the portal so a
// display name always corresponds to the app name.
func slugifyDisplayName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

func newAppsCreateCmd() *cobra.Command {
	var (
		name, displayName, description string
		source, appType                string
		commitURL, image               string
		storage                        bool
		cloudImageName, cloudChannel   string
		enclave                        string
		size                           string
	)
	cmd := &cobra.Command{
		Use:   "create --name <name> --source <upload|github|package|cloud_image> [flags]",
		Short: "Create a new app",
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if name == "" || source == "" {
				return fmt.Errorf("--name and --source are required")
			}
			// A friendly display name must reduce to the canonical app name
			// (lowercase, spaces to hyphens, other characters dropped). Checked
			// locally for a fast, clear error; the server enforces it too.
			if displayName != "" {
				canonical := strings.ToLower(strings.TrimSpace(name))
				if slug := slugifyDisplayName(displayName); slug != canonical {
					return fmt.Errorf("--display-name %q must reduce to --name %q (it reduces to %q): lowercase, spaces become hyphens, other characters are dropped", displayName, canonical, slug)
				}
			}
			body := map[string]interface{}{"name": name, "source_type": source}
			putStr(body, "display_name", displayName)
			putStr(body, "description", description)
			putStr(body, "app_type", appType)
			putStr(body, "commit_url", commitURL)
			putStr(body, "container_image", image)
			putStr(body, "cloud_image_name", cloudImageName)
			putStr(body, "cloud_image_channel", cloudChannel)
			putStr(body, "enclave_id", enclave)
			// container_port is platform-allocated (the app listens on $PORT);
			// not a user input. See bug #43.
			if storage {
				body["container_storage"] = true
			}
			if size != "" {
				slug, err := normalizeInstanceSize(size)
				if err != nil {
					return err
				}
				body["instance_size"] = slug
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			app, err := client.CreateApp(cmd.Context(), body)
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(os.Stderr, "Created app %s (%s)", output.Str(app, "name"), output.Str(app, "id"))
			}
			return output.Emit(env.Format, app, func() output.Table {
				return kvTable(app, []string{"name", "id", "app_type", "source_type", "status"})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "app name (DNS-safe)")
	f.StringVar(&displayName, "display-name", "", "human-friendly name")
	f.StringVar(&description, "description", "", "description")
	f.StringVar(&source, "source", "", "source type: upload|github|package|cloud_image")
	f.StringVar(&appType, "type", "", "app type: wasm|container")
	f.StringVar(&commitURL, "commit-url", "", "GitHub commit URL (github source)")
	f.StringVar(&image, "image", "", "container image ref (package source)")
	f.BoolVar(&storage, "storage", false, "request encrypted container storage")
	f.StringVar(&cloudImageName, "cloud-image-name", "", "cloud image name (cloud_image source)")
	f.StringVar(&cloudChannel, "cloud-image-channel", "", "cloud image channel (cloud_image source)")
	f.StringVar(&enclave, "enclave", "", "target enclave id")
	f.StringVar(&size, "size", "", "container VM size: micro|small|medium|large|xlarge (or Confidential-* name; default micro, fixed at creation)")
	return cmd
}

// normalizeInstanceSize maps a --size value to the wire slug. Accepts the bare
// slug (micro..xlarge) or the canonical Confidential-* name, case-insensitive.
func normalizeInstanceSize(v string) (string, error) {
	slug := strings.ToLower(strings.TrimSpace(v))
	slug = strings.TrimPrefix(slug, "confidential-")
	switch slug {
	case "micro", "small", "medium", "large", "xlarge":
		return slug, nil
	}
	return "", fmt.Errorf("--size must be one of micro, small, medium, large, xlarge (got %q); see 'privasys apps sizes'", v)
}

func newAppsSizesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sizes",
		Short: "List the Confidential-* container VM sizes and rates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			sizes, err := client.InstanceSizes(cmd.Context())
			if err != nil {
				return err
			}
			return output.Emit(env.Format, map[string]interface{}{"sizes": sizes}, func() output.Table {
				rows := make([][]string, 0, len(sizes))
				for _, s := range sizes {
					perHour := numField(s, "credits_per_hour")
					rows = append(rows, []string{
						output.Str(s, "slug"),
						output.Str(s, "size"),
						fmt.Sprintf("%d", int64(numField(s, "vcpu"))),
						fmt.Sprintf("%d GB", int64(numField(s, "ram_gb"))),
						fmt.Sprintf("%d GB", int64(numField(s, "storage_gb"))),
						// The meter tick: charged per started hour (decision 2026-07-13).
						fmt.Sprintf("%d", int64(perHour)),
						// 720h = the price book's published month (Micro £43.20/mo).
						fmt.Sprintf("£%.2f", perHour*720/1_000_000),
					})
				}
				return output.Table{
					Headers: []string{"SLUG", "SIZE", "VCPU", "RAM", "STORAGE", "CREDITS/HOUR", "~/MONTH"},
					Rows:    rows,
				}
			})
		},
	}
}

// currentStoreFields returns an app's existing store_* listing as an
// UpdateStoreListing payload. The server overwrites ALL store fields on every
// call (no partial merge), so any command that changes a subset must seed from
// this to avoid wiping the rest. display_name is left out on purpose — the
// server treats it as an optional pointer and leaves it untouched when absent.
func currentStoreFields(app map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"store_tagline":       output.Str(app, "store_tagline"),
		"store_description":   output.Str(app, "store_description"),
		"store_category":      output.Str(app, "store_category"),
		"store_icon_url":      output.Str(app, "store_icon_url"),
		"store_screenshots":   app["store_screenshots"],
		"store_privacy_url":   output.Str(app, "store_privacy_url"),
		"store_tos_url":       output.Str(app, "store_tos_url"),
		"store_website_url":   output.Str(app, "store_website_url"),
		"store_support_email": output.Str(app, "store_support_email"),
		"store_keywords":      output.Str(app, "store_keywords"),
	}
}

func newAppsRenameCmd() *cobra.Command {
	var title string
	cmd := &cobra.Command{
		Use:   "rename <app> --title <title>",
		Short: "Change an app's display title (the canonical name/slug is immutable)",
		Long: `Sets the app's friendly display title (display_name), e.g. "Web Search (Brave)".

The title must reduce to the canonical app name (lowercase, spaces become
hyphens, other characters dropped) — the canonical name/slug itself cannot be
changed. Pass an empty --title to reset the title to the canonical name.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("title") {
				return fmt.Errorf("--title is required")
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			// Fetch the app: we need its canonical name for the slug check, and
			// its existing store fields to echo back (UpdateStoreListing does a
			// full overwrite of the listing, so a bare title change would wipe
			// the rest).
			cur, gerr := client.GetApp(cmd.Context(), appID)
			if gerr != nil {
				return gerr
			}
			canonical := output.Str(cur, "name")
			// Local slug check for a fast, clear error (the server enforces it too).
			if t := strings.TrimSpace(title); t != "" {
				if slug := slugifyDisplayName(t); slug != canonical {
					return fmt.Errorf("title %q must reduce to the app name %q (it reduces to %q): lowercase, spaces become hyphens, other characters are dropped", t, canonical, slug)
				}
			}
			fields := currentStoreFields(cur)
			fields["display_name"] = title
			app, err := client.UpdateStoreListing(cmd.Context(), appID, fields)
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Renamed %s to %q", args[0], output.Str(app, "display_name"))
			}
			return output.Emit(env.Format, app, func() output.Table {
				return kvTable(app, []string{"name", "display_name", "id"})
			})
		},
	}
	cmd.Flags().StringVar(&title, "title", "", "display title (must reduce to the canonical app name)")
	return cmd
}

func newAppsStoreListingCmd() *cobra.Command {
	var description, category, tagline, iconURL, privacyURL, tosURL, websiteURL, supportEmail, keywords string
	var screenshots []string
	cmd := &cobra.Command{
		Use:   "store-listing <app>",
		Short: "Set an app's App Store listing (Description + Category are required before deploy)",
		Long:  "Sets the App Store listing fields for an app. A Description and a Category are required before the app can be deployed or published. Only the flags you pass are updated.",
		Args:  cobra.ExactArgs(1),
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
			// Seed from the current listing so unspecified fields survive — the
			// server overwrites ALL store fields on every call.
			cur, gerr := client.GetApp(cmd.Context(), appID)
			if gerr != nil {
				return gerr
			}
			fields := currentStoreFields(cur)
			changed := false
			for flag, key := range map[string]string{
				"description": "store_description", "category": "store_category",
				"tagline": "store_tagline", "icon-url": "store_icon_url",
				"privacy-url": "store_privacy_url", "tos-url": "store_tos_url",
				"website-url": "store_website_url", "support-email": "store_support_email",
				"keywords": "store_keywords",
			} {
				if cmd.Flags().Changed(flag) {
					v, _ := cmd.Flags().GetString(flag)
					fields[key] = v
					changed = true
				}
			}
			if cmd.Flags().Changed("screenshot") {
				fields["store_screenshots"] = screenshots
				changed = true
			}
			if !changed {
				return fmt.Errorf("nothing to set; pass at least --description and --category")
			}
			app, err := client.UpdateStoreListing(cmd.Context(), appID, fields)
			if err != nil {
				return err
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Updated store listing for %s", args[0])
			}
			return output.Emit(env.Format, app, func() output.Table {
				return kvTable(app, []string{"name", "id", "store_description", "store_category", "published"})
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&description, "description", "", "store description (required before deploy)")
	f.StringVar(&category, "category", "", "store category (required before deploy)")
	f.StringVar(&tagline, "tagline", "", "short tagline")
	f.StringVar(&iconURL, "icon-url", "", "icon URL")
	f.StringVar(&privacyURL, "privacy-url", "", "privacy policy URL")
	f.StringVar(&tosURL, "tos-url", "", "terms-of-service URL")
	f.StringVar(&websiteURL, "website-url", "", "website URL")
	f.StringVar(&supportEmail, "support-email", "", "support email")
	f.StringVar(&keywords, "keywords", "", "comma-separated keywords")
	f.StringArrayVar(&screenshots, "screenshot", nil, "screenshot URL (repeatable)")
	return cmd
}

func newAppsDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <app-id>",
		Short: "Delete an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if !force && !env.NoInput {
				fmt.Fprintf(os.Stderr, "Delete app %s? Re-run with --force to confirm.\n", args[0])
				return fmt.Errorf("confirmation required")
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}
			if err := client.DeleteApp(cmd.Context(), appID); err != nil {
				return err
			}
			output.Success(cmd.OutOrStdout(), "Deleted")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete without confirmation")
	return cmd
}

func newAppsUploadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload <app-id> <file.cwasm>",
		Short: "Upload a .cwasm artifact (wasm apps)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			app, err := client.UploadCwasm(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Uploaded.")
			return output.Emit(env.Format, app, func() output.Table {
				return kvTable(app, []string{"name", "id", "cwasm_hash", "cwasm_size", "status"})
			})
		},
	}
}

func newAppsVersionsCmd() *cobra.Command {
	c := &cobra.Command{Use: "versions", Short: "Manage app versions"}
	c.AddCommand(
		&cobra.Command{
			Use:   "list <app-id>",
			Short: "List versions",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				env, err := loadEnv(cmd)
				if err != nil {
					return err
				}
				client, err := apiClient(cmd, env)
				if err != nil {
					return err
				}
				vs, err := client.ListVersions(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return output.Emit(env.Format, vs, func() output.Table {
					rows := make([][]string, 0, len(vs))
					for _, v := range vs {
						rows = append(rows, []string{
							versionLabel(v), output.Str(v, "id"), output.Str(v, "status"),
						})
					}
					return output.Table{Headers: []string{"VERSION", "ID", "STATUS"}, Rows: rows}
				})
			},
		},
		newVersionsCreateCmd(),
		newVersionsStageCmd(),
		newVersionsPendingCmd(),
		newVersionsPromoteCmd(),
		newVersionsRevokeCmd(),
	)
	return c
}

// versionCreateBody builds the source-aware create body from the flags, erroring
// if zero or more than one source flag is set. version (semver) is optional.
func versionCreateBody(cmd *cobra.Command) (map[string]string, error) {
	commitURL, _ := cmd.Flags().GetString("commit-url")
	image, _ := cmd.Flags().GetString("image")
	channel, _ := cmd.Flags().GetString("channel")
	version, _ := cmd.Flags().GetString("version")
	body := map[string]string{}
	set := 0
	if commitURL != "" {
		body["commit_url"] = commitURL
		set++
	}
	if image != "" {
		body["image"] = image
		set++
	}
	if channel != "" {
		body["channel"] = channel
		set++
	}
	if set == 0 {
		return nil, fmt.Errorf("one of --commit-url (github), --image (package), or --channel (cloud_image) is required")
	}
	if set > 1 {
		return nil, fmt.Errorf("pass only one of --commit-url / --image / --channel (matching the app's source)")
	}
	if version != "" {
		body["version"] = version
	}
	return body, nil
}

func newVersionsCreateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "create <app> [--commit-url <url> | --image <ref> | --channel <ch>] [--version vX.Y.Z]",
		Short: "Record a new version (github commit, package image, or cloud-image channel)",
		Long: `Ships a new version of an app. Pass the field matching the app's source:
  --commit-url  github apps (verifies a GPG-signed commit, triggers a build)
  --image       package apps (a pre-built container image ref)
  --channel     cloud_image apps (re-pin the latest cached disk for a channel)
Optionally set --version to a strictly-incrementing semver (vX.Y.Z); omitted
auto-bumps the patch.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			body, err := versionCreateBody(cmd)
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
			v, err := client.CreateVersion(cmd.Context(), appID, body)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, v, func() output.Table {
				return kvTable(v, []string{"semver", "version_number", "id", "github_commit", "container_image", "status"})
			})
		},
	}
	c.Flags().String("commit-url", "", "GitHub commit URL (github apps)")
	c.Flags().String("image", "", "container image ref (package apps)")
	c.Flags().String("channel", "", "cloud-image channel (cloud_image apps)")
	c.Flags().String("version", "", "semver to assign (vX.Y.Z; default auto-bump patch)")
	return c
}

// emitFanout renders a per-vault fan-out result ({staged|promoted, quorum,
// vaults:[…]}) and writes a one-line human summary to stderr.
func emitFanout(cmd *cobra.Command, env *Env, res map[string]interface{}, verb string) error {
	if !env.Quiet && env.Format == "table" {
		if n, ok := res[verb]; ok {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s %v/%v vaults\n", verb, n, res["quorum"])
		}
	}
	return output.Emit(env.Format, res, func() output.Table {
		rows := [][]string{}
		if vs, ok := res["vaults"].([]interface{}); ok {
			for _, v := range vs {
				m, _ := v.(map[string]interface{})
				rows = append(rows, []string{
					output.Str(m, "vault"), output.Str(m, "ok"),
					output.Str(m, "pending_id"), output.Str(m, "policy_version"),
					output.Str(m, "error"),
				})
			}
		}
		return output.Table{Headers: []string{"VAULT", "OK", "PENDING", "POLICY_VER", "ERROR"}, Rows: rows}
	})
}

// confirm asks a y/N question. It refuses to guess in non-interactive contexts
// (--no-input or a non-TTY), where the caller must pass an explicit --yes.
func confirm(cmd *cobra.Command, env *Env, prompt string) (bool, error) {
	if env.NoInput || !stdoutIsTTY() {
		return false, fmt.Errorf("refusing to prompt; pass --yes to proceed")
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

// newAppsUpgradeCmd is the guided upgrade-approval flow for a vault-backed app.
func newAppsUpgradeCmd() *cobra.Command {
	var enclaveID string
	var pendingID int
	var yes bool
	cmd := &cobra.Command{
		Use:   "upgrade <app> [version]",
		Short: "Approve a vault-backed app's upgrade so its data unlocks for the new version",
		Long: `Guided upgrade approval. When a vault-backed app's measurement changes (you
deploy a new version, or the enclave is upgraded), the vault locks the data
until you, the app owner, approve the new measurement. The platform cannot do
this for you.

This stages the new measurement, shows what is being approved (the staged
profile and per-vault progress), and promotes it after your confirmation. Use
the discrete ` + "`apps versions stage|pending|promote|revoke`" + ` commands for finer
control or for scripting.`,
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
			ctx := cmd.Context()
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			vid, err := resolveVersionRef(ctx, client, appID, argOr(args, 1, ""))
			if err != nil {
				return err
			}
			enc, err := resolveEnclaveRef(ctx, client, appID, enclaveID)
			if err != nil {
				return err
			}

			staged, err := client.StageProfile(ctx, appID, vid, enc)
			if err != nil {
				return err
			}
			if !env.Quiet && env.Format == "table" {
				fmt.Fprintf(cmd.ErrOrStderr(), "staged %v/%v vaults\n", staged["staged"], staged["quorum"])
			}

			// Show exactly what is about to be approved (the verify-before-approve step).
			pend, err := client.ListPending(ctx, appID, vid)
			if err != nil {
				return err
			}
			if !env.Quiet && env.Format == "table" {
				if buf, mErr := json.MarshalIndent(pend, "", "  "); mErr == nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Measurement to approve (review the digest against your build):\n%s\n", buf)
				}
			}

			if !yes {
				ok, cErr := confirm(cmd, env, fmt.Sprintf("Promote pending #%d for %s? This releases the data key to the new version.", pendingID, args[0]))
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}

			res, err := promoteWithStepUp(cmd, env, client, appID, vid, pendingID, nil)
			if err != nil {
				return err
			}
			return emitFanout(cmd, env, res, "promoted")
		},
	}
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "target enclave id (default: the only compatible one)")
	cmd.Flags().IntVar(&pendingID, "pending", 0, "pending profile id to promote (default 0)")
	cmd.Flags().BoolVar(&yes, "yes", false, "promote without an interactive confirmation")
	return cmd
}

// newAppsUpdateCmd is the one-shot, approve-before-deploy upgrade: ship a new
// version (optional), approve the measurement for a vault-backed app, then cut
// over (the server stops the old version before starting the new one).
func newAppsUpdateCmd() *cobra.Command {
	var enclaveID string
	var pendingID int
	var yes, watch bool
	cmd := &cobra.Command{
		Use:   "update <app> [--image <ref> | --commit-url <url> | --channel <ch>] [--version vX.Y.Z]",
		Short: "Ship + approve + deploy a new version in one step (approve-before-deploy)",
		Long: `Guided end-to-end upgrade in the correct order:
  1. ship the new version (from --image/--commit-url/--channel; omit to use the latest ready one)
  2. for a vault-backed app: stage the new measurement, show it, and promote it after your confirm
  3. deploy — the server stops the old version before starting the new one (no overlap)

This is the safe path: the data key is authorised BEFORE the cutover, so the new
version loads cleanly with no locked-data window.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			app, err := client.GetApp(ctx, appID)
			if err != nil {
				return err
			}

			// 1. Ship a new version if a source flag was given; else use the latest.
			vid := ""
			if hasVersionSource(cmd) {
				body, berr := versionCreateBody(cmd)
				if berr != nil {
					return berr
				}
				v, cerr := client.CreateVersion(ctx, appID, body)
				if cerr != nil {
					return cerr
				}
				vid = output.Str(v, "id")
				if !env.Quiet {
					output.Success(cmd.ErrOrStderr(), "shipped %s", versionLabel(v))
				}
			} else {
				vid, err = resolveVersionRef(ctx, client, appID, "")
				if err != nil {
					return err
				}
			}

			enc, err := resolveEnclaveRef(ctx, client, appID, enclaveID)
			if err != nil {
				return err
			}

			// 2. Approve (vault-backed apps only): stage -> show -> confirm -> promote.
			// A handle is present only once the app has been deployed before, i.e.
			// this is an upgrade; the first deploy fills the key and needs no approval.
			if output.Str(app, "vault_key_handle") != "" {
				staged, serr := client.StageProfile(ctx, appID, vid, enc)
				if serr != nil {
					return serr
				}
				if !env.Quiet && env.Format == "table" {
					fmt.Fprintf(cmd.ErrOrStderr(), "staged %v/%v vaults\n", staged["staged"], staged["quorum"])
				}
				pend, perr := client.ListPending(ctx, appID, vid)
				if perr != nil {
					return perr
				}
				if !env.Quiet && env.Format == "table" {
					if buf, mErr := json.MarshalIndent(pend, "", "  "); mErr == nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "Measurement to approve (check the digest against your build):\n%s\n", buf)
					}
				}
				if !yes {
					ok, cErr := confirm(cmd, env, fmt.Sprintf("Promote pending #%d for %s? This authorises the data key for the new version.", pendingID, args[0]))
					if cErr != nil {
						return cErr
					}
					if !ok {
						return fmt.Errorf("aborted")
					}
				}
				if _, prerr := promoteWithStepUp(cmd, env, client, appID, vid, pendingID, nil); prerr != nil {
					return prerr
				}
				if !env.Quiet {
					output.Success(cmd.ErrOrStderr(), "approved")
				}
			}

			// 3. Deploy. The server gate verifies the measurement is promoted and
			// stops the running version before starting the new one (no overlap).
			dep, derr := client.DeployVersion(ctx, appID, vid, enc, "", "", "")
			if derr != nil {
				return derr
			}
			if !watch {
				return output.Emit(env.Format, dep, func() output.Table {
					return kvTable(dep, []string{"id", "status", "enclave_host", "hostname"})
				})
			}
			return watchDeployment(cmd, client, env, appID, output.Str(dep, "id"))
		},
	}
	cmd.Flags().String("commit-url", "", "GitHub commit URL (github apps)")
	cmd.Flags().String("image", "", "container image ref (package apps)")
	cmd.Flags().String("channel", "", "cloud-image channel (cloud_image apps)")
	cmd.Flags().String("version", "", "semver to assign (vX.Y.Z; default auto-bump patch)")
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "target enclave id (default: the only compatible one)")
	cmd.Flags().IntVar(&pendingID, "pending", 0, "pending profile id to promote (default 0)")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not prompt before promoting")
	cmd.Flags().BoolVar(&watch, "watch", false, "poll until the deployment is active or failed")
	return cmd
}

// hasVersionSource reports whether any new-version source flag was provided.
func hasVersionSource(cmd *cobra.Command) bool {
	for _, f := range []string{"commit-url", "image", "channel"} {
		if v, _ := cmd.Flags().GetString(f); v != "" {
			return true
		}
	}
	return false
}

// newAppsRotateKeyCmd rotates a vault-backed app's volume encryption key.
func newAppsRotateKeyCmd() *cobra.Command {
	var enclaveID string
	var yes bool
	cmd := &cobra.Command{
		Use:   "rotate-key <app> [version]",
		Short: "Rotate a vault-backed app's data encryption key (online, no data re-encryption)",
		Long: `Rotates the vault-held key that wraps your app's encrypted volume. This is key
hygiene, NOT an upgrade: the data on disk is never re-encrypted and the app stays
running. The platform provisions a new key generation, re-keys the volume's LUKS
keyslots from the old key to the new (both open the volume across the switch, so
no failure can lock your data), advances the key handle, and retires the old
generation.

Use it on a schedule, or after a suspected exposure of a vault share. The app
must be running on the target enclave (its live measurement is what the new key
generation authorises).`,
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
			ctx := cmd.Context()
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			vid, err := resolveVersionRef(ctx, client, appID, argOr(args, 1, ""))
			if err != nil {
				return err
			}
			enc, err := resolveEnclaveRef(ctx, client, appID, enclaveID)
			if err != nil {
				return err
			}
			if !yes {
				ok, cErr := confirm(cmd, env, fmt.Sprintf("Rotate the data encryption key for %s? The app keeps running and data is preserved.", args[0]))
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			res, err := client.RotateKey(ctx, appID, vid, enc)
			if err != nil {
				return err
			}
			if !env.Quiet && env.Format == "table" {
				if nh := output.Str(res, "new_handle"); nh != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "rotated to %s\n", nh)
				}
				if warn := output.Str(res, "warning"); warn != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn)
				}
			}
			return output.Emit(env.Format, res, func() output.Table {
				return kvTable(res, []string{"rotated", "old_handle", "new_handle", "warning"})
			})
		},
	}
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "enclave the app runs on (default: the only compatible one)")
	cmd.Flags().BoolVar(&yes, "yes", false, "rotate without an interactive confirmation")
	return cmd
}

// newAppsExportKeyCmd exports a vault-backed app's data encryption key to a
// local file (the owner taking their key out — portability / escrow).
func newAppsExportKeyCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "export-key <app>",
		Short: "Export your app's data encryption key to a local file (DANGEROUS)",
		Long: `Exports the vault-held key that protects your app's encrypted storage and writes
the raw key to a local file. The vaults each return only their share; the key is
reconstructed on your machine. This is YOUR key — export it for escrow, backup,
or to move your data off-platform.

DANGER: this writes raw key material to disk. The material is never printed and
never leaves your machine through this CLI. Depending on policy, export may
require a fresh WebAuthn step-up from your wallet/passkey.

The file is written with 0600 permissions; the command prints only the path and
a fingerprint, never the key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return fmt.Errorf("--out <file> is required (the key is written to a local file only)")
			}
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			target, err := client.GetVaultExportTarget(ctx, appID)
			if err != nil {
				return err
			}
			tok, err := auth.AccessToken(ctx, env.Cfg.Issuer)
			if err != nil {
				return err
			}
			claims, err := auth.Claims(tok)
			if err != nil {
				return err
			}
			sub, _ := claims["sub"].(string)
			attTok, _ := auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server")

			material, res, err := secrets.Export(ctx, secrets.ExportParams{
				Issuer: env.Cfg.Issuer, Bearer: tok, Sub: sub, Handle: target.Handle,
				Endpoints: target.Endpoints, Threshold: target.Threshold,
				MRENCLAVE: target.MRENCLAVE, AttServer: target.AttestationServer, AttToken: attTok,
				RequireStepUp: target.RequireStepUp, Assert: walletStepUpApprover(),
				GenerationSize: secrets.AppDEKGenerationSize,
			})
			if err != nil {
				return err
			}
			werr := os.WriteFile(out, material, 0o600)
			for i := range material {
				material[i] = 0
			}
			if werr != nil {
				return fmt.Errorf("write %s: %w", out, werr)
			}
			if !env.Quiet {
				output.Success(cmd.ErrOrStderr(), "Wrote %s (%d/%d vaults, %s)",
					out, res.Retrieved, res.Total, res.Fingerprint)
			}
			return output.Emit(env.Format, map[string]interface{}{
				"handle": res.Handle, "path": out, "fingerprint": res.Fingerprint,
				"vaults": res.Retrieved, "written": true,
			}, func() output.Table {
				return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
					{"handle", res.Handle},
					{"path", out},
					{"fingerprint", res.Fingerprint},
				}}
			})
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "write the raw key to this local file (required)")
	return cmd
}

// versionLabel renders a human version label: "<semver> · <src>:<short> · <date>"
// (e.g. "v1.2.3 · git:a1b2c3d · 23 Jun 2026"). Shared by `versions list` and the
// upgrade/deploy output (the enclave-upgrade plan, D). Falls back gracefully when
// fields are missing.
func versionLabel(v map[string]interface{}) string {
	sv := output.Str(v, "semver")
	if sv == "" {
		if n := output.Str(v, "version_number"); n != "" {
			sv = "v" + n
		}
	}
	src, hash := versionSrcHash(v)
	parts := make([]string, 0, 3)
	if sv != "" {
		parts = append(parts, sv)
	}
	if src != "" && hash != "" {
		parts = append(parts, src+":"+hash)
	}
	if d := shortDate(output.Str(v, "created_at")); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, " · ")
}

// versionSrcHash returns the source prefix (git/pkg/img/wasm) and a short
// identifier for a version.
func versionSrcHash(v map[string]interface{}) (string, string) {
	if c := output.Str(v, "github_commit"); c != "" {
		return "git", shortHash(c)
	}
	img := output.Str(v, "container_image")
	if strings.HasPrefix(img, "cloud-image:") {
		segs := strings.Split(img, ":")
		return "img", segs[len(segs)-1]
	}
	if img != "" {
		return "pkg", shortImageRef(img)
	}
	if h := output.Str(v, "cwasm_hash"); h != "" {
		return "wasm", shortHash(h)
	}
	return "", ""
}

func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 7 {
		return h[:7]
	}
	return h
}

func shortImageRef(img string) string {
	if i := strings.Index(img, "@sha256:"); i >= 0 {
		return shortHash(img[i+len("@sha256:"):])
	}
	// No digest: show the tag (the ':' after the last path '/', so host:port is ignored).
	if i := strings.LastIndex(img, ":"); i >= 0 && i > strings.LastIndex(img, "/") {
		return img[i+1:]
	}
	return img
}

func shortDate(s string) string {
	if s == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2 Jan 2006")
	}
	return ""
}

// newAppsMigrateConstellationCmd moves a vault-backed app's key onto a new
// constellation without re-encrypting data (graceful vault rotation).
func newAppsMigrateConstellationCmd() *cobra.Command {
	var target string
	var yes bool
	cmd := &cobra.Command{
		Use:   "migrate-constellation <app>",
		Short: "Move a vault-backed app's data key onto a new vault constellation (online, no re-encrypt)",
		Long: `Migrates the vault key that wraps your app's encrypted volume from its current
constellation onto another one — the safe form of a vault (MRENCLAVE) rotation.
The platform reserves a new key on the target constellation, re-keys the volume's
LUKS slots from the old key to the new (both open the volume across the switch, so
no failure can lock your data), advances the pointer, and retires the old key on
the old constellation. The data on disk is never re-encrypted and the app keeps
running. Defaults to the currently-active constellation.`,
		Args: cobra.ExactArgs(1),
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
			if !yes {
				ok, cErr := confirm(cmd, env, fmt.Sprintf("Migrate %s's data key to the %s constellation? The app keeps running and data is preserved.", args[0], ifElse(target == "", "active", target)))
				if cErr != nil {
					return cErr
				}
				if !ok {
					return fmt.Errorf("aborted")
				}
			}
			res, err := client.MigrateConstellation(cmd.Context(), appID, target)
			if err != nil {
				return err
			}
			if !env.Quiet && env.Format == "table" {
				if w := output.Str(res, "warning"); w != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
				}
			}
			return output.Emit(env.Format, res, func() output.Table {
				return kvTable(res, []string{"migrated", "from_constellation", "to_constellation", "old_handle", "new_handle", "reason", "warning"})
			})
		},
	}
	cmd.Flags().StringVar(&target, "to", "", "target constellation id (default: the active constellation)")
	cmd.Flags().BoolVar(&yes, "yes", false, "migrate without an interactive confirmation")
	return cmd
}

// ifElse returns a when cond, else b.
func ifElse(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// argOr returns args[i] when present, else def.
func argOr(args []string, i int, def string) string {
	if i < len(args) {
		return args[i]
	}
	return def
}

// resolveVersionRef resolves a version ref (id or version number) to its id,
// defaulting to the latest version when ref is empty.
func resolveVersionRef(ctx context.Context, client *api.Client, appID, ref string) (string, error) {
	vs, err := client.ListVersions(ctx, appID)
	if err != nil {
		return "", err
	}
	if len(vs) == 0 {
		return "", fmt.Errorf("app has no versions")
	}
	if ref == "" {
		return output.Str(vs[len(vs)-1], "id"), nil
	}
	for _, v := range vs {
		if output.Str(v, "id") == ref || output.Str(v, "version_number") == ref {
			return output.Str(v, "id"), nil
		}
	}
	return "", fmt.Errorf("version %q not found", ref)
}

// resolveEnclaveRef picks the target enclave: the flag if set, else the single
// compatible enclave, else an error asking for --enclave.
func resolveEnclaveRef(ctx context.Context, client *api.Client, appID, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	encs, err := client.CompatibleEnclaves(ctx, appID)
	if err != nil {
		return "", err
	}
	switch len(encs) {
	case 1:
		return output.Str(encs[0], "id"), nil
	case 0:
		return "", fmt.Errorf("no compatible enclaves; pass --enclave <id>")
	default:
		return "", fmt.Errorf("multiple compatible enclaves; pass --enclave <id>")
	}
}

func newVersionsStageCmd() *cobra.Command {
	var enclaveID string
	c := &cobra.Command{
		Use:   "stage <app> [version]",
		Short: "Stage the new measurement for a version on the vault constellation (owner-only)",
		Long:  "Proposes the measurement (enclave MRTD + image digest) that a later promote will authorise. Staging grants no key access on its own. Needed when an enclave or app upgrade changes the measurement of a vault-backed app.",
		Args:  cobra.RangeArgs(1, 2),
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
			enc, err := resolveEnclaveRef(cmd.Context(), client, appID, enclaveID)
			if err != nil {
				return err
			}
			res, err := client.StageProfile(cmd.Context(), appID, vid, enc)
			if err != nil {
				return err
			}
			return emitFanout(cmd, env, res, "staged")
		},
	}
	c.Flags().StringVar(&enclaveID, "enclave", "", "target enclave id (default: the only compatible one)")
	return c
}

func newVersionsPendingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pending <app> [version]",
		Short: "Show staged-but-unpromoted profiles and per-vault progress (owner-only)",
		Args:  cobra.RangeArgs(1, 2),
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
			res, err := client.ListPending(cmd.Context(), appID, vid)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, res, func() output.Table {
				rows := [][]string{}
				if vs, ok := res["vaults"].([]interface{}); ok {
					for _, v := range vs {
						m, _ := v.(map[string]interface{})
						rows = append(rows, []string{
							output.Str(m, "vault"), output.Str(m, "ok"),
							output.Str(m, "pending_id"), output.Str(m, "error"),
						})
					}
				}
				return output.Table{Headers: []string{"VAULT", "OK", "PENDING", "ERROR"}, Rows: rows}
			})
		},
	}
}

// promoteWithStepUp promotes pendingID for (appID, vid). When the app's vault
// key gates promote on an operation-bound WebAuthn step-up (VAULT_REQUIRE_STEPUP),
// it drives the browser passkey ceremony and promotes with the resulting
// operation-bound token as the bearer — the management-service forwards that
// bearer to the vault, which recomputes the binding and releases the key.
// Otherwise it promotes with the ordinary owner bearer. approvalTokens carries
// any separation-of-duties co-sign tokens.
func promoteWithStepUp(cmd *cobra.Command, env *Env, client *api.Client, appID, vid string, pendingID int, approvalTokens []string) (map[string]interface{}, error) {
	ctx := cmd.Context()
	tgt, err := client.GetVaultExportTarget(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("resolve vault key for step-up: %w", err)
	}
	if !tgt.RequireStepUp {
		return client.PromoteProfile(ctx, appID, vid, pendingID, approvalTokens...)
	}
	digest, policyVersion, err := pendingStepUpBinding(ctx, client, appID, vid, pendingID)
	if err != nil {
		return nil, err
	}
	bearer, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return nil, err
	}
	// Advisory context so the approver's wallet shows what they are approving —
	// the app's friendly name and the target version/source — instead of only a
	// hex digest. Best-effort: a lookup failure just omits that hint.
	actx := promoteApprovalContext(ctx, client, appID, vid)
	stepTok, err := secrets.RequestStepUpViaBrowser(ctx, env.Cfg.Issuer, bearer, "promote",
		tgt.Handle, digest, policyVersion, actx, secrets.OpenBrowser, cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
	// The step-up token carries the owner sub AND the operation-bound webauthn
	// proof, so it satisfies both the owner principal and the OidcStepUp condition
	// in one bearer. Swap it in only for this promote call.
	sc := *client
	sc.Token = stepTok
	return sc.PromoteProfile(ctx, appID, vid, pendingID, approvalTokens...)
}

// promoteApprovalContext builds the advisory display context (app friendly name
// + target version label) attached to a promote step-up, so the approver's
// wallet shows what they are approving rather than only a hex digest. All fields
// are best-effort — a lookup failure just yields a thinner card, never an error
// (the operation itself is unaffected: context is not part of the vault binding).
func promoteApprovalContext(ctx context.Context, client *api.Client, appID, vid string) map[string]string {
	// app_id + version_id let the approver's wallet query the (public,
	// no-running-enclave) release-provenance endpoint itself, so it can show the
	// published release and a GitHub compare (old→new) link — mgmt-computed, not
	// relayed through this CLI.
	c := map[string]string{"app_id": appID, "version_id": vid}
	if app, err := client.GetApp(ctx, appID); err == nil {
		name := output.Str(app, "display_name")
		if name == "" {
			name = output.Str(app, "name")
		}
		if name != "" {
			c["app_name"] = name
		}
	}
	if vs, err := client.ListVersions(ctx, appID); err == nil {
		for _, v := range vs {
			if output.Str(v, "id") == vid || output.Str(v, "semver") == vid ||
				output.Str(v, "version_number") == vid {
				if lbl := versionLabel(v); lbl != "" {
					c["version"] = lbl
				}
				break
			}
		}
	}
	return c
}

// pendingStepUpBinding pulls the operation-binding inputs (profile_binding_digest
// and the key's current policy_version) for pendingID from the enriched pending
// list, so the step-up token binds this exact promote and nothing else.
func pendingStepUpBinding(ctx context.Context, client *api.Client, appID, vid string, pendingID int) (string, uint32, error) {
	pend, err := client.ListPending(ctx, appID, vid)
	if err != nil {
		return "", 0, err
	}
	vaults, _ := pend["vaults"].([]interface{})
	for _, v := range vaults {
		vm, _ := v.(map[string]interface{})
		plist, _ := vm["pending"].([]interface{})
		for _, p := range plist {
			pm, _ := p.(map[string]interface{})
			if int(jsonNum(pm["id"])) != pendingID {
				continue
			}
			digest, _ := pm["profile_binding_digest"].(string)
			if digest == "" {
				return "", 0, fmt.Errorf("pending #%d carries no binding digest; the platform may be too old for step-up promote", pendingID)
			}
			return digest, uint32(jsonNum(pm["policy_version"])), nil
		}
	}
	return "", 0, fmt.Errorf("pending profile #%d not found; stage the measurement first", pendingID)
}

// jsonNum coerces a decoded JSON number (float64) to a float, 0 if absent.
func jsonNum(v interface{}) float64 {
	f, _ := v.(float64)
	return f
}

func newVersionsPromoteCmd() *cobra.Command {
	var pendingID int
	var approvalTokens []string
	c := &cobra.Command{
		Use:   "promote <app> [version]",
		Short: "Promote (approve) a staged measurement so the vault releases the data key to it (owner-only)",
		Long: `Authorises the new measurement. This is the act that lets the upgraded enclave/app reconstruct the data-encryption key. Only the app owner can promote; the platform cannot.

If the app opted into separation-of-duties co-sign, pass a fresh co-sign token from a SECOND team approver with --approval-token (repeatable).`,
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
			res, err := promoteWithStepUp(cmd, env, client, appID, vid, pendingID, approvalTokens)
			if err != nil {
				return err
			}
			return emitFanout(cmd, env, res, "promoted")
		},
	}
	c.Flags().IntVar(&pendingID, "pending", 0, "pending profile id (stable across vaults; default 0)")
	c.Flags().StringArrayVar(&approvalTokens, "approval-token", nil, "co-sign approval token from a second approver (repeatable; only for co-sign apps)")
	return c
}

func newAppsCosignCmd() *cobra.Command {
	var enable, disable bool
	c := &cobra.Command{
		Use:   "cosign <app> (--enable | --disable)",
		Short: "Toggle separation-of-duties co-sign on promote (owner-only)",
		Long: `When enabled, promoting a new measurement requires a fresh approval token
from a SECOND team approver (approver != proposer). Takes effect on the next
vault key reservation/re-key that re-authors the policy.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if enable == disable {
				return fmt.Errorf("pass exactly one of --enable or --disable")
			}
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
			app, err := client.SetVaultCosign(cmd.Context(), appID, enable)
			if err != nil {
				return err
			}
			if !env.Quiet {
				state := "disabled"
				if enable {
					state = "enabled"
				}
				output.Success(cmd.ErrOrStderr(), "co-sign on promote %s for %s", state, output.Str(app, "name"))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&enable, "enable", false, "require co-sign on promote")
	c.Flags().BoolVar(&disable, "disable", false, "do not require co-sign on promote")
	return c
}

func newVersionsRevokeCmd() *cobra.Command {
	var pendingID int
	c := &cobra.Command{
		Use:   "revoke <app> [version]",
		Short: "Drop a staged-but-unpromoted profile (owner-only)",
		Args:  cobra.RangeArgs(1, 2),
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
			res, err := client.RevokeProfile(cmd.Context(), appID, vid, pendingID)
			if err != nil {
				return err
			}
			return emitFanout(cmd, env, res, "revoked")
		},
	}
	c.Flags().IntVar(&pendingID, "pending", 0, "pending profile id (default 0)")
	return c
}

func newAppsLocationsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "locations <app-id>",
		Short: "List the locations this app can be deployed to",
		Args:  cobra.ExactArgs(1),
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
			locs, err := client.DeployLocations(cmd.Context(), appID)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, map[string]interface{}{"locations": locs}, func() output.Table {
				rows := make([][]string, 0, len(locs))
				for _, l := range locs {
					rows = append(rows, []string{
						output.Str(l, "code"), output.Str(l, "label"),
						output.Str(l, "tee_type"), output.Str(l, "provider"),
					})
				}
				return output.Table{Headers: []string{"CODE", "LOCATION", "TEE", "PROVIDER"}, Rows: rows}
			})
		},
	}
}

func newAppsDeployCmd() *cobra.Command {
	var versionID, enclaveID, location, size, tenancy string
	var watch bool
	cmd := &cobra.Command{
		Use:   "deploy <app-id>",
		Short: "Deploy a version to an enclave",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if size != "" {
				slug, serr := normalizeInstanceSize(size)
				if serr != nil {
					return serr
				}
				size = slug
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(cmd.Context(), client, args[0])
			if err != nil {
				return err
			}

			// Default to the latest version when not specified.
			if versionID == "" {
				vs, err := client.ListVersions(cmd.Context(), appID)
				if err != nil {
					return err
				}
				if len(vs) == 0 {
					return fmt.Errorf("no versions; create one with `apps versions create` or `apps upload`")
				}
				versionID = output.Str(vs[len(vs)-1], "id")
			}

			if tenancy != "" && tenancy != "mutualised" && tenancy != "dedicated" {
				return fmt.Errorf("--tenancy must be mutualised or dedicated")
			}
			// Placement: adopters pick a location, not an enclave. An
			// explicit --enclave (admin) still wins. Otherwise resolve the
			// location: use --location, or auto-pick when there is exactly
			// one. Dedicated provisions a whole VM in the platform's region,
			// so it needs no location.
			if tenancy != "dedicated" && enclaveID == "" && location == "" {
				locs, err := client.DeployLocations(cmd.Context(), appID)
				if err != nil {
					return err
				}
				switch {
				case len(locs) == 1:
					location = output.Str(locs[0], "code")
				case len(locs) == 0:
					return fmt.Errorf("no locations available for this app")
				default:
					codes := make([]string, 0, len(locs))
					for _, l := range locs {
						codes = append(codes, output.Str(l, "code"))
					}
					return fmt.Errorf("multiple locations available; pass --location <%s>", strings.Join(codes, "|"))
				}
			}

			dep, err := client.DeployVersion(cmd.Context(), appID, versionID, enclaveID, location, size, tenancy)
			if err != nil {
				return err
			}
			if !watch {
				return output.Emit(env.Format, dep, func() output.Table {
					return kvTable(dep, []string{"id", "status", "enclave_host", "hostname", "instance_size"})
				})
			}
			return watchDeployment(cmd, client, env, appID, output.Str(dep, "id"))
		},
	}
	cmd.Flags().StringVar(&versionID, "version", "", "version id (default: latest)")
	cmd.Flags().StringVar(&location, "location", "", "deploy location code, e.g. europe-west9 (default: the only one available; see `apps locations`)")
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "target enclave id (admin override; adopters use --location)")
	cmd.Flags().StringVar(&size, "size", "", "container VM size for THIS deployment: micro|small|medium|large|xlarge (default: the app's size; redeploying with a new size is the resize)")
	cmd.Flags().StringVar(&tenancy, "tenancy", "", "mutualised (default, shared CVM) or dedicated (a whole confidential VM, Medium/Large only)")
	cmd.Flags().BoolVar(&watch, "watch", false, "poll until the deployment is active or failed")
	return cmd
}

// deployPhase maps a (status, container_state) pair to a friendly phase label
// and whether the deployment has finished (and failed). It collapses the raw
// status churn ("starting"/"pulling"/...) into a few human stages.
func deployPhase(status, container string) (label string, done, failed bool) {
	switch status {
	case "active", "deployed", "running":
		return "active", true, false
	case "failed", "error", "stopped":
		return status, true, true
	}
	switch container {
	case "pulling":
		return "pulling image", false, false
	case "running":
		return "starting container", false, false
	case "", "unknown":
		return "preparing", false, false
	default:
		return container, false, false
	}
}

// watchDeployment polls a deployment until it is active or fails. On a terminal
// it shows a single live spinner line that updates in place (one line, friendly
// phase); on a pipe/agent it prints one plain line per phase transition (no
// repetition). Used by `apps deploy --watch` and `apps update --watch`.
func watchDeployment(cmd *cobra.Command, client *api.Client, env *Env, appID, depID string) error {
	w := cmd.ErrOrStderr()
	tty := output.IsTTY(w)
	spin := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
	start := time.Now()
	deadline := start.Add(5 * time.Minute)
	lastLabel := ""
	si := 0
	var cur map[string]interface{}
	var lastPoll time.Time
	var activeSince time.Time
	// After the deployment goes active, wait this long for a gateway to pull a
	// route set including the new hostname before declaring success — so the
	// endpoint is actually reachable (closes the deploy/attest propagation race).
	const routeWait = 25 * time.Second

	clear := func() {
		if tty {
			fmt.Fprint(w, "\r\033[K")
		}
	}

	for {
		if lastPoll.IsZero() || time.Since(lastPoll) >= 3*time.Second {
			deps, err := client.ListDeployments(cmd.Context(), appID)
			if err != nil {
				clear()
				return err
			}
			cur = nil
			for _, d := range deps {
				if output.Str(d, "id") == depID {
					cur = d
					break
				}
			}
			lastPoll = time.Now()
		}

		if cur != nil {
			label, done, failed := deployPhase(output.Str(cur, "status"), output.Str(cur, "container_state"))
			elapsed := int(time.Since(start).Seconds())

			if done && failed {
				clear()
				// A vault-backed app whose measurement just changed has its
				// data key locked pending owner approval (the upgrade gate).
				fmt.Fprintf(w, "deployment %s (%ds)\n", label, elapsed)
				fmt.Fprintf(w, "hint: if this app uses vault-backed storage and you changed the version or enclave, the data key may be locked pending approval — run: privasys apps upgrade %s\n", appID)
				return fmt.Errorf("deployment %s ended in status %q", depID, output.Str(cur, "status"))
			}
			if done { // active: gate success on the gateway route having propagated
				if activeSince.IsZero() {
					activeSince = time.Now()
				}
				routeReady, _ := cur["route_ready"].(bool)
				if routeReady {
					clear()
					output.Success(w, "active, routable (%ds)", elapsed)
					return output.Emit(env.Format, cur, func() output.Table {
						return kvTable(cur, []string{"id", "status", "container_state", "enclave_host", "hostname"})
					})
				}
				if time.Since(activeSince) > routeWait {
					clear()
					output.Success(w, "active (%ds)", elapsed)
					fmt.Fprintf(w, "warning: the app is active but route propagation to the gateway is unconfirmed; the endpoint may not be reachable yet — retry `attest` shortly\n")
					return output.Emit(env.Format, cur, func() output.Table {
						return kvTable(cur, []string{"id", "status", "container_state", "enclave_host", "hostname"})
					})
				}
				// Active but not yet routable — keep waiting (and rendering).
				label = "waiting for gateway route"
			}

			if tty {
				fmt.Fprintf(w, "\r\033[K%s %s (%ds)", string(spin[si%len(spin)]), label, elapsed)
				si++
			} else if label != lastLabel {
				fmt.Fprintf(w, "%s…\n", label)
				lastLabel = label
			}
		}

		if time.Now().After(deadline) {
			clear()
			return fmt.Errorf("timed out watching deployment %s", depID)
		}
		wait := 3 * time.Second
		if tty {
			wait = 120 * time.Millisecond // smooth spinner between polls
		}
		select {
		case <-cmd.Context().Done():
			clear()
			return cmd.Context().Err()
		case <-time.After(wait):
		}
	}
}

func newAppsDeploymentsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deployments <app-id>",
		Short: "List an app's deployments",
		Args:  cobra.ExactArgs(1),
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
			deps, err := client.ListDeployments(cmd.Context(), appID)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, deps, func() output.Table {
				rows := make([][]string, 0, len(deps))
				for _, d := range deps {
					rows = append(rows, []string{
						output.Str(d, "id"), output.Str(d, "status"),
						output.Str(d, "container_state"), output.Str(d, "enclave_host"),
					})
				}
				return output.Table{Headers: []string{"ID", "STATUS", "CONTAINER", "ENCLAVE"}, Rows: rows}
			})
		},
	}
}

func newAppsStopCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "stop <app-id> <deployment-id>",
		Short: "Stop a running deployment",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			dep, err := client.StopDeployment(cmd.Context(), args[0], args[1], force)
			if err != nil {
				return err
			}
			return output.Emit(env.Format, dep, func() output.Table {
				return kvTable(dep, []string{"id", "status"})
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "force stop")
	return cmd
}

func newAppsAPICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api <app-id>",
		Short: "List the app's exported functions (schema)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			schema, err := client.Schema(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, schema, func() output.Table {
				rows := schemaRows(schema)
				return output.Table{Headers: []string{"INTERFACE", "FUNCTION", "ROLE", "PARAMS", "RESULTS"}, Rows: rows}
			})
		},
	}
}

func newAppsMcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp <app-id>",
		Short: "Show the app's MCP tool manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			m, err := client.MCP(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, m, nil)
		},
	}
}

func newAppsCallCmd() *cobra.Command {
	var data, host, token, path, attServer string
	var noChallenge, doAttest bool
	cmd := &cobra.Command{
		Use:   "call <app-id> <function>",
		Short: "Call an app function directly over RA-TLS (verifies the enclave first)",
		Long: `Calls an app function by connecting to its enclave over RA-TLS, verifying the
attestation, and sending the request directly — the control plane is never in
the data path. Your token is presented to the app for its own auth. The
response streams to stdout, so chunked and SSE endpoints work.

By default the enclave is verified locally (RA-TLS + fresh-nonce report-data
binding) without contacting the attestation server. Pass --attest for full
quote verification (genuine TEE + TCB) against the attestation server.

  --data    JSON request body, or @file
  --host    enclave gateway FQDN (default: resolved from the app)
  --token   token to present to the app (default: your access token)
  --path    container endpoint path (default: /<function>)
  --attest  also verify the quote against the attestation server
  --no-challenge  skip the fresh-nonce challenge (deterministic verify)`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			var body []byte
			if data != "" {
				var perr error
				if body, perr = parseJSONDataArg(data); perr != nil {
					return perr
				}
			}

			// Resolve app metadata (type/name/manifest) and the deployment
			// hostname. Metadata only — the data itself goes direct. --host
			// skips the hostname lookup.
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			appName, aType, serverName := args[0], "wasm", host
			app, err := client.GetApp(ctx, appID)
			if err != nil {
				return err
			}
			if n := output.Str(app, "name"); n != "" {
				appName = n
			}
			if t := appType(app); t != "" {
				aType = t
			}
			if path == "" && aType == "container" {
				path = resolveContainerPath(app, args[1])
			}
			if serverName == "" {
				serverName, err = client.ActiveDeploymentHost(ctx, appID)
				if err != nil {
					return fmt.Errorf("%w; pass --host <enclave-fqdn>", err)
				}
			}

			appTok := token
			if appTok == "" {
				appTok, err = auth.AccessToken(ctx, env.Cfg.Issuer)
				if err != nil {
					return err
				}
			}
			// The attestation-server call is opt-in (--attest); by default we
			// verify the RA-TLS report-data binding locally without it.
			attURL, attTok := "", ""
			if doAttest {
				attURL = attServer
				if attTok, _ = auth.AccessTokenForAudience(ctx, env.Cfg.Issuer, "attestation-server"); attTok == "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "warning: could not mint an attestation-server token; verifying report-data binding only")
				}
			}
			var nonce []byte
			if !noChallenge {
				nonce = ratls.NewNonce()
			}

			status, err := ratls.Call(ctx, ratls.CallParams{
				Host: serverName, ServerName: serverName, AppName: appName, AppType: aType,
				Function: args[1], Path: path, Body: body, AppToken: appTok,
				Challenge: nonce, AttServerURL: attURL, AttServerTok: attTok,
			}, os.Stdout)
			if err != nil {
				return err
			}
			fmt.Println()
			if status >= 400 {
				return fmt.Errorf("app returned status %d", status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&data, "data", "", "JSON request body, or @file to read from a file")
	cmd.Flags().StringVar(&host, "host", "", "enclave gateway FQDN (default: resolved from the app)")
	cmd.Flags().StringVar(&token, "token", "", "token to present to the app (default: your access token)")
	cmd.Flags().StringVar(&path, "path", "", "container endpoint path (default: /<function>)")
	cmd.Flags().BoolVar(&doAttest, "attest", false, "also verify the quote against the attestation server")
	cmd.Flags().StringVar(&attServer, "att-server", "https://as.privasys.org/verify", "attestation server verify endpoint (with --attest)")
	cmd.Flags().BoolVar(&noChallenge, "no-challenge", false, "skip the fresh-nonce challenge (deterministic verify)")
	return cmd
}

// resolveContainerPath maps a function name to a container endpoint via the
// app's privasys.json tool manifest, falling back to /<function>.
func resolveContainerPath(app map[string]interface{}, function string) string {
	mcp, ok := app["container_mcp"].(map[string]interface{})
	if ok {
		if tools, ok := mcp["tools"].([]interface{}); ok {
			for _, t := range tools {
				tm, ok := t.(map[string]interface{})
				if ok && output.Str(tm, "name") == function {
					if ep := output.Str(tm, "endpoint"); ep != "" {
						return ep
					}
				}
			}
		}
	}
	return "/" + function
}

func newAppsBuildsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "builds <app-id>",
		Short: "List build jobs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			builds, err := client.ListBuilds(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return output.Emit(env.Format, builds, func() output.Table {
				rows := make([][]string, 0, len(builds))
				for _, b := range builds {
					rows = append(rows, []string{
						output.Str(b, "id"), output.Str(b, "status"),
						output.Str(b, "github_commit"), output.Str(b, "run_url"),
					})
				}
				return output.Table{Headers: []string{"ID", "STATUS", "COMMIT", "RUN"}, Rows: rows}
			})
		},
	}
}

// --- helpers ---

func putStr(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func kvTable(m map[string]interface{}, keys []string) output.Table {
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		if v := output.Str(m, k); v != "" {
			rows = append(rows, []string{k, v})
		}
	}
	return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

func ifPresent(prefix, v string) string {
	if v == "" {
		return ""
	}
	return prefix + v
}

// schemaRows flattens an app schema (top-level functions + interfaces) into
// table rows.
func schemaRows(schema map[string]interface{}) [][]string {
	var rows [][]string
	addFns := func(iface string, fns []interface{}) {
		for _, fn := range fns {
			fm, ok := fn.(map[string]interface{})
			if !ok {
				continue
			}
			role := output.Str(fm, "role")
			if role == "" {
				role = "inference"
			}
			rows = append(rows, []string{iface, output.Str(fm, "name"), role, countOf(fm, "params"), countOf(fm, "results")})
		}
	}
	if fns, ok := schema["functions"].([]interface{}); ok {
		addFns("", fns)
	}
	if ifaces, ok := schema["interfaces"].([]interface{}); ok {
		for _, i := range ifaces {
			im, ok := i.(map[string]interface{})
			if !ok {
				continue
			}
			if fns, ok := im["functions"].([]interface{}); ok {
				addFns(output.Str(im, "name"), fns)
			}
		}
	}
	return rows
}

func countOf(m map[string]interface{}, key string) string {
	if a, ok := m[key].([]interface{}); ok {
		return fmt.Sprintf("%d", len(a))
	}
	return "0"
}

// --- config + actions (role-tagged tools on the schema/RPC surface) ---

// newAppsConfigureCmd configures an app by calling its role:config tool through
// the control-plane relay. A successful call lifts the configure-then-freeze
// gate. With no --set/--data it describes the required config.
func newAppsConfigureCmd() *cobra.Command {
	var set []string
	var data string
	cmd := &cobra.Command{
		Use:   "configure <app-id>",
		Short: "Configure an app (applies its owner setup; lifts the freeze gate)",
		Long: `Submits owner configuration to the app's image-declared configure section
(or a legacy role:config tool) via the control plane. A successful call lifts the
configure-then-freeze gate. With no --set/--data, prints the config target and its
field count.

  --set key=value   config value (repeatable)
  --data            JSON config body, or @file (overrides --set)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			schema, err := client.Schema(ctx, appID)
			if err != nil {
				return err
			}
			name, fn := configDescriptor(schema)
			if name == "" || fn == nil {
				return fmt.Errorf("app declares no configuration")
			}
			if len(set) == 0 && data == "" {
				return output.Emit(env.Format, fn, func() output.Table {
					return output.Table{Headers: []string{"CONFIG", "FIELDS"}, Rows: [][]string{{name, countConfigFields(fn)}}}
				})
			}
			body, err := buildToolBody(set, data)
			if err != nil {
				return err
			}
			res, err := client.Rpc(ctx, appID, name, body)
			if err != nil {
				return err
			}
			if e := rpcResultError(res); e != "" {
				return fmt.Errorf("configure failed: %s", e)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "configured (freeze gate lifted)")
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&set, "set", nil, "config value key=value (repeatable)")
	cmd.Flags().StringVar(&data, "data", "", "JSON config body (or @file); overrides --set")
	return cmd
}

// newAppsActionCmd runs an app action tool via the control-plane relay and, when
// the tool declares x-privasys.progress, polls the named status tool to a
// terminal state, printing progress.
func newAppsActionCmd() *cobra.Command {
	var arg []string
	var data string
	cmd := &cobra.Command{
		Use:   "action <app-id> <name>",
		Short: "Run an app action tool, polling progress to completion",
		Long: `Invokes a role:action tool by name via the control plane. If the tool declares
a progress channel (x-privasys.progress), polls the status tool until it reaches
a terminal state.

  --arg key=value   input value (repeatable)
  --data            JSON body, or @file (overrides --arg)`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			appID, err := resolveAppID(ctx, client, args[0])
			if err != nil {
				return err
			}
			schema, err := client.Schema(ctx, appID)
			if err != nil {
				return err
			}
			fn := functionByName(schema, args[1])
			if fn == nil {
				return fmt.Errorf("no such function %q (see `app schema`)", args[1])
			}
			body, err := buildToolBody(arg, data)
			if err != nil {
				return err
			}
			res, err := client.Rpc(ctx, appID, args[1], body)
			if err != nil {
				return err
			}
			if e := rpcResultError(res); e != "" {
				return fmt.Errorf("action failed: %s", e)
			}
			out := cmd.OutOrStdout()
			prog := progressSpec(fn)
			if prog == nil {
				fmt.Fprintln(out, "done")
				return nil
			}
			for i := 0; i < 600; i++ {
				time.Sleep(2 * time.Second)
				st, err := client.Rpc(ctx, appID, prog.tool, map[string]interface{}{})
				if err != nil {
					return err
				}
				stu := unwrapRpcResult(st)
				state := output.Str(stu, prog.stateField)
				msg := ""
				if prog.messageField != "" {
					msg = output.Str(stu, prog.messageField)
				}
				fmt.Fprintf(out, "\r%-10s %-50s", state, msg)
				if contains(prog.success, state) {
					fmt.Fprintf(out, "\n")
					return nil
				}
				if contains(prog.failure, state) {
					return fmt.Errorf("\naction failed: %s", msg)
				}
			}
			return fmt.Errorf("action did not finish in time")
		},
	}
	cmd.Flags().StringArrayVar(&arg, "arg", nil, "input key=value (repeatable)")
	cmd.Flags().StringVar(&data, "data", "", "JSON body (or @file); overrides --arg")
	return cmd
}

// --- helpers for config/action ---

func schemaFunctions(schema map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	if fns, ok := schema["functions"].([]interface{}); ok {
		for _, f := range fns {
			if fm, ok := f.(map[string]interface{}); ok {
				out = append(out, fm)
			}
		}
	}
	return out
}

func functionByRole(schema map[string]interface{}, role string) map[string]interface{} {
	for _, fm := range schemaFunctions(schema) {
		if output.Str(fm, "role") == role {
			return fm
		}
	}
	return nil
}

// configDescriptor resolves the app's owner-configuration target: the dedicated
// top-level `configure` section, or a legacy role:config tool. Returns the RPC
// name and a descriptor map (for display), or ("", nil) when none is declared.
func configDescriptor(schema map[string]interface{}) (string, map[string]interface{}) {
	if cfg, ok := schema["configure"].(map[string]interface{}); ok && len(cfg) > 0 {
		name := output.Str(cfg, "name")
		if name == "" {
			if f := output.Str(cfg, "function"); f != "" {
				name = f
			} else if ep := output.Str(cfg, "endpoint"); ep != "" {
				name = strings.TrimPrefix(ep, "/")
			}
		}
		return name, cfg
	}
	if fn := functionByRole(schema, "config"); fn != nil {
		return output.Str(fn, "name"), fn
	}
	return "", nil
}

// countConfigFields returns the field count for a config descriptor: the
// `inputSchema.properties` length for a `configure` section, else the legacy
// tool's `params` count.
func countConfigFields(fn map[string]interface{}) string {
	if is, ok := fn["inputSchema"].(map[string]interface{}); ok {
		if props, ok := is["properties"].(map[string]interface{}); ok {
			return fmt.Sprintf("%d", len(props))
		}
	}
	return countOf(fn, "params")
}

func functionByName(schema map[string]interface{}, name string) map[string]interface{} {
	for _, fm := range schemaFunctions(schema) {
		if output.Str(fm, "name") == name {
			return fm
		}
	}
	return nil
}

// buildToolBody turns --set/--arg key=value pairs (or a --data JSON blob) into a
// request body.
func buildToolBody(kv []string, data string) (interface{}, error) {
	if data != "" {
		b, err := parseJSONDataArg(data)
		if err != nil {
			return nil, err
		}
		var v interface{}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("--data is not valid JSON: %w", err)
		}
		return v, nil
	}
	m := map[string]interface{}{}
	for _, p := range kv {
		i := strings.IndexByte(p, '=')
		if i < 0 {
			return nil, fmt.Errorf("invalid key=value %q", p)
		}
		m[p[:i]] = p[i+1:]
	}
	return m, nil
}

// rpcResultError returns a non-empty error string if the RPC envelope carries a
// transport error or a WIT-level Err (returns[0].value.err); otherwise "".
func rpcResultError(res map[string]interface{}) string {
	if e, ok := res["error"].(string); ok && e != "" {
		return e
	}
	if rs, ok := res["returns"].([]interface{}); ok && len(rs) > 0 {
		if r0, ok := rs[0].(map[string]interface{}); ok {
			if val, ok := r0["value"].(map[string]interface{}); ok {
				if e, ok := val["err"]; ok && e != nil {
					return fmt.Sprintf("%v", e)
				}
			}
		}
	}
	return ""
}

// unwrapRpcResult returns the inner record of an RPC response: container apps
// return their JSON directly; wasm apps wrap it as returns[0].value(.ok).
func unwrapRpcResult(res map[string]interface{}) map[string]interface{} {
	if rs, ok := res["returns"].([]interface{}); ok && len(rs) > 0 {
		if r0, ok := rs[0].(map[string]interface{}); ok {
			if val, ok := r0["value"].(map[string]interface{}); ok {
				if okv, ok := val["ok"].(map[string]interface{}); ok {
					return okv
				}
				return val
			}
		}
	}
	return res
}

type progSpec struct {
	tool, stateField, progressField, messageField string
	success, failure                              []string
}

func progressSpec(fn map[string]interface{}) *progSpec {
	xp, ok := fn["x_privasys"].(map[string]interface{})
	if !ok {
		return nil
	}
	p, ok := xp["progress"].(map[string]interface{})
	if !ok {
		return nil
	}
	ps := &progSpec{
		tool:          output.Str(p, "tool"),
		stateField:    output.Str(p, "stateField"),
		progressField: output.Str(p, "progressField"),
		messageField:  output.Str(p, "messageField"),
	}
	if ps.tool == "" || ps.stateField == "" {
		return nil
	}
	if t, ok := p["terminal"].(map[string]interface{}); ok {
		ps.success = anyToStrSlice(t["success"])
		ps.failure = anyToStrSlice(t["failure"])
	}
	return ps
}

func anyToStrSlice(v interface{}) []string {
	a, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, fmt.Sprintf("%v", x))
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
