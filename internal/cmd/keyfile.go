// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// restrictKeyFile makes a freshly written key file readable by its owner only.
// On Unix the 0600 mode it was created with already does that. Windows ignores
// Unix modes, so the file would inherit its folder's ACL (often readable by
// other local accounts): drop the inherited entries and grant the current user
// alone. Returns a warning to show when that could not be done.
func restrictKeyFile(path string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	user := os.Getenv("USERNAME")
	if d := os.Getenv("USERDOMAIN"); d != "" && user != "" {
		user = d + `\` + user
	}
	if user == "" {
		return fmt.Sprintf("could not determine your Windows account: restrict access to %s yourself", path)
	}
	out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", user+":F").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("could not restrict %s to your account (icacls: %v, %s): restrict access to it yourself", path, err, out)
	}
	return ""
}
