// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/output"
)

const releasesAPI = "https://api.github.com/repos/Privasys/cli/releases/latest"

func newUpdateCmd() *cobra.Command {
	var checkOnly bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the CLI to the latest release",
		Long: `Checks the latest release and updates the CLI in place. Installs made with a
package manager are delegated to it (scoop, Homebrew); script or manual installs
are replaced directly with the released binary after its checksum is verified
against the release's checksums.txt.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			w := cmd.ErrOrStderr()

			current := strings.TrimPrefix(resolveVersion(), "v")
			latest, err := latestReleaseVersion(ctx)
			if err != nil {
				return fmt.Errorf("check latest release: %w", err)
			}
			upToDate := !versionLess(current, latest)
			if checkOnly {
				status := fmt.Sprintf("update available: %s", latest)
				if upToDate {
					status = "up to date"
				}
				return output.Emit(env.Format, map[string]any{
					"current": current, "latest": latest, "up_to_date": upToDate,
				}, func() output.Table {
					return output.Table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
						{"current", current}, {"latest", latest}, {"status", status},
					}}
				})
			}
			if upToDate {
				output.Success(w, "Already up to date (%s)", current)
				return nil
			}

			exe, err := os.Executable()
			if err != nil {
				return err
			}
			// Resolve symlinks so a manual install reached through a symlink
			// replaces the real binary. Keep the original path if resolution
			// fails — e.g. a Windows directory junction (scoop's `current`) that
			// EvalSymlinks refuses: a blank path would misdetect the install
			// channel and drop into the self-replace path by mistake.
			if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil && resolved != "" {
				exe = resolved
			}

			// A package-manager install is the package manager's to update:
			// replacing the binary underneath it would desynchronise its state.
			switch channel := detectInstallChannel(exe); channel {
			case "scoop":
				// scoop refuses to update a running app, and THIS process is a
				// running privasys. Hand off to a detached updater that waits for
				// us (and any other instances) to exit, so we don't self-block.
				if runtime.GOOS == "windows" {
					return spawnDetachedScoopUpdate(w)
				}
				fmt.Fprintf(w, "Installed via scoop; running: scoop update privasys\n")
				return runTool(cmd, "scoop", "update", "privasys")
			case "brew":
				fmt.Fprintf(w, "Installed via Homebrew; running: brew upgrade privasys\n")
				return runTool(cmd, "brew", "upgrade", "privasys")
			case "package":
				fmt.Fprintf(w, "Installed from a .deb/.rpm package. Download the %s package from:\n  https://github.com/Privasys/cli/releases/latest\n", latest)
				return nil
			}

			fmt.Fprintf(w, "Updating %s -> %s …\n", current, latest)
			if err := selfReplace(ctx, exe, latest); err != nil {
				return err
			}
			output.Success(w, "Updated to %s (%s)", latest, exe)
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "only report whether a newer release exists")
	return cmd
}

// detectInstallChannel classifies how this binary was installed from its path.
func detectInstallChannel(exe string) string {
	// Normalise both separators explicitly: filepath.ToSlash only converts on
	// Windows, and this classification must behave identically everywhere.
	p := strings.ToLower(strings.ReplaceAll(exe, `\`, "/"))
	switch {
	case strings.Contains(p, "/scoop/"):
		return "scoop"
	case strings.Contains(p, "/cellar/") || strings.Contains(p, "/homebrew/") || strings.Contains(p, "/linuxbrew/"):
		return "brew"
	case runtime.GOOS == "linux" && (p == "/usr/bin/privasys" || p == "/usr/sbin/privasys"):
		// The .deb/.rpm packages install here; dpkg/rpm owns the file.
		return "package"
	default:
		return "direct"
	}
}

// spawnDetachedScoopUpdate works around scoop refusing to update a running app:
// this very process is a running privasys, so `scoop update` would abort on it.
// It opens a detached console that waits for this process to exit (and prompts
// to close any other privasys instances, e.g. MCP servers), then runs the
// update — and returns immediately so this process can exit and unblock scoop.
func spawnDetachedScoopUpdate(w io.Writer) error {
	pid := os.Getpid()
	ps := fmt.Sprintf(
		"Write-Host 'Updating privasys via scoop...';"+
			"Wait-Process -Id %d -ErrorAction SilentlyContinue;"+
			"while ($true) {"+
			"  $o = @(Get-Process privasys -ErrorAction SilentlyContinue);"+
			"  if ($o.Count -eq 0) { break }"+
			"  Write-Host 'Other privasys processes are running (they block scoop). Close them, then press Enter:' -ForegroundColor Yellow;"+
			"  $o | Select-Object Id,ProcessName | Format-Table | Out-Host;"+
			"  Read-Host | Out-Null"+
			"};"+
			"scoop update privasys;"+
			"Write-Host '';"+
			"Read-Host 'Done. Press Enter to close' | Out-Null",
		pid)
	// `start` launches an independent console window that survives this process.
	c := exec.Command("cmd", "/c", "start", "privasys update", "powershell",
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	if err := c.Start(); err != nil {
		fmt.Fprintf(w, "Installed via scoop. Close running privasys processes, then run: scoop update privasys\n")
		return nil
	}
	fmt.Fprintf(w, "Installed via scoop. Since scoop cannot update a running app, an updater\n")
	fmt.Fprintf(w, "opened in a new window; it runs once this process (and any other privasys\n")
	fmt.Fprintf(w, "instances, such as MCP servers) exit.\n")
	return nil
}

// runTool executes a package manager inheriting the terminal.
func runTool(cmd *cobra.Command, name string, args ...string) error {
	c := exec.CommandContext(cmd.Context(), name, args...)
	c.Stdout = cmd.OutOrStdout()
	c.Stderr = cmd.ErrOrStderr()
	c.Stdin = os.Stdin
	return c.Run()
}

// latestReleaseVersion fetches the latest release tag (without the v prefix).
func latestReleaseVersion(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub releases API: HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no tag_name in the latest release")
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// versionLess reports whether a < b for dotted numeric versions ("0.22.0").
// Unparseable versions (dev builds) compare as older, so `update` proceeds.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		na, nb := 0, 0
		if i < len(pa) {
			na, _ = strconv.Atoi(strings.TrimFunc(pa[i], func(r rune) bool { return r < '0' || r > '9' }))
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(strings.TrimFunc(pb[i], func(r rune) bool { return r < '0' || r > '9' }))
		}
		if na != nb {
			return na < nb
		}
	}
	return false
}

// selfReplace downloads the released archive for this OS/arch, verifies its
// sha256 against the release's checksums.txt, extracts the binary, and swaps it
// into place atomically (via a rename dance, so it works while running).
func selfReplace(ctx context.Context, exe, version string) error {
	if exe == "" {
		return fmt.Errorf("could not determine the running binary path; download %s from https://github.com/Privasys/cli/releases/latest", version)
	}
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	asset := fmt.Sprintf("privasys_%s_%s_%s.%s", version, runtime.GOOS, runtime.GOARCH, ext)
	base := fmt.Sprintf("https://github.com/Privasys/cli/releases/download/v%s/", version)

	archive, err := download(ctx, base+asset)
	if err != nil {
		return fmt.Errorf("download %s: %w", asset, err)
	}
	sums, err := download(ctx, base+"checksums.txt")
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	if err := verifyChecksum(sums, asset, archive); err != nil {
		return err
	}

	binName := "privasys"
	if runtime.GOOS == "windows" {
		binName = "privasys.exe"
	}
	bin, err := extractFile(archive, ext, binName)
	if err != nil {
		return fmt.Errorf("extract %s: %w", binName, err)
	}

	// Write next to the target so the final rename stays on one filesystem.
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".privasys-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// Windows cannot overwrite a running executable, but it CAN be renamed:
	// move the live binary aside, then move the new one into its place.
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("stage current binary aside: %w", err)
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		_ = os.Rename(old, exe) // roll back
		os.Remove(tmpPath)
		return fmt.Errorf("install new binary: %w", err)
	}
	os.Remove(old) // best effort; on Windows it lingers until the process exits
	return nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// verifyChecksum checks data against the `<sha256>  <name>` lines of checksums.txt.
func verifyChecksum(sums []byte, name string, data []byte) error {
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			want = f[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("checksums.txt has no entry for %s", name)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s want %s", name, got, want)
	}
	return nil
}

// extractFile pulls a single file out of a tar.gz or zip archive.
func extractFile(archive []byte, ext, name string) ([]byte, error) {
	if ext == "zip" {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == name {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, 256<<20))
			}
		}
		return nil, fmt.Errorf("%s not in archive", name)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == name {
			return io.ReadAll(io.LimitReader(tr, 256<<20))
		}
	}
	return nil, fmt.Errorf("%s not in archive", name)
}
