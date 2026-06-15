// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"os/exec"
	"runtime"
)

// openURL attempts to open a URL in the default browser. Best-effort: returns
// an error the caller can ignore (the URL is always printed too).
func openURL(u string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	case "darwin":
		return exec.Command("open", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}
