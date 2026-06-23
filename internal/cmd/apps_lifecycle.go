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
)

func newAppsCreateCmd() *cobra.Command {
	var (
		name, displayName, description string
		source, appType                string
		commitURL, image               string
		storage                        bool
		cloudImageName, cloudChannel   string
		enclave                        string
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

			res, err := client.PromoteProfile(ctx, appID, vid, pendingID)
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
				if _, prerr := client.PromoteProfile(ctx, appID, vid, pendingID); prerr != nil {
					return prerr
				}
				if !env.Quiet {
					output.Success(cmd.ErrOrStderr(), "approved")
				}
			}

			// 3. Deploy. The server gate verifies the measurement is promoted and
			// stops the running version before starting the new one (no overlap).
			dep, derr := client.DeployVersion(ctx, appID, vid, enc)
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

func newVersionsPromoteCmd() *cobra.Command {
	var pendingID int
	c := &cobra.Command{
		Use:   "promote <app> [version]",
		Short: "Promote (approve) a staged measurement so the vault releases the data key to it (owner-only)",
		Long:  "Authorises the new measurement. This is the act that lets the upgraded enclave/app reconstruct the data-encryption key. Only the app owner can promote; the platform cannot.",
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
			res, err := client.PromoteProfile(cmd.Context(), appID, vid, pendingID)
			if err != nil {
				return err
			}
			return emitFanout(cmd, env, res, "promoted")
		},
	}
	c.Flags().IntVar(&pendingID, "pending", 0, "pending profile id (stable across vaults; default 0)")
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

func newAppsDeployCmd() *cobra.Command {
	var versionID, enclaveID string
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

			// Resolve a compatible enclave when not specified.
			if enclaveID == "" {
				encs, err := client.CompatibleEnclaves(cmd.Context(), appID)
				if err != nil {
					return err
				}
				if len(encs) == 1 {
					enclaveID = output.Str(encs[0], "id")
				} else if len(encs) == 0 {
					return fmt.Errorf("no compatible enclaves available")
				} else {
					if env.NoInput {
						return fmt.Errorf("multiple compatible enclaves; pass --enclave <id>")
					}
					return fmt.Errorf("multiple compatible enclaves; pass --enclave <id> (see `apps deploy --help`)")
				}
			}

			dep, err := client.DeployVersion(cmd.Context(), appID, versionID, enclaveID)
			if err != nil {
				return err
			}
			if !watch {
				return output.Emit(env.Format, dep, func() output.Table {
					return kvTable(dep, []string{"id", "status", "enclave_host", "hostname"})
				})
			}
			return watchDeployment(cmd, client, env, appID, output.Str(dep, "id"))
		},
	}
	cmd.Flags().StringVar(&versionID, "version", "", "version id (default: latest)")
	cmd.Flags().StringVar(&enclaveID, "enclave", "", "target enclave id (default: the only compatible one)")
	cmd.Flags().BoolVar(&watch, "watch", false, "poll until the deployment is active or failed")
	return cmd
}

func watchDeployment(cmd *cobra.Command, client *api.Client, env *Env, appID, depID string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		deps, err := client.ListDeployments(cmd.Context(), appID)
		if err != nil {
			return err
		}
		var cur map[string]interface{}
		for _, d := range deps {
			if output.Str(d, "id") == depID {
				cur = d
				break
			}
		}
		if cur != nil {
			st := output.Str(cur, "status")
			cs := output.Str(cur, "container_state")
			fmt.Fprintf(os.Stderr, "status=%s%s\n", st, ifPresent(" container=", cs))
			switch st {
			case "active", "deployed", "running":
				return output.Emit(env.Format, cur, func() output.Table {
					return kvTable(cur, []string{"id", "status", "container_state", "enclave_host", "hostname"})
				})
			case "failed", "error", "stopped":
				// If this is a vault-backed app whose measurement just changed,
				// the data key is locked pending owner approval (the upgrade gate).
				fmt.Fprintf(cmd.ErrOrStderr(),
					"hint: if this app uses vault-backed storage and you changed the version or enclave, the data key may be locked pending approval — run: privasys apps upgrade %s\n",
					appID)
				return fmt.Errorf("deployment %s ended in status %q", depID, st)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out watching deployment %s", depID)
		}
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case <-time.After(3 * time.Second):
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
				return output.Table{Headers: []string{"INTERFACE", "FUNCTION", "PARAMS", "RESULTS"}, Rows: rows}
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
				body = []byte(data)
				if data[0] == '@' {
					b, rerr := os.ReadFile(data[1:])
					if rerr != nil {
						return rerr
					}
					body = b
				}
				if !json.Valid(body) {
					return fmt.Errorf("--data is not valid JSON")
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
			rows = append(rows, []string{iface, output.Str(fm, "name"), countOf(fm, "params"), countOf(fm, "results")})
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
