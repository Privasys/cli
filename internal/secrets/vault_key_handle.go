// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"fmt"
	"strconv"
	"strings"
)

// CheckVaultKeyHandle checks that a handle the control plane gives for key
// name in vault vaultID (from the catalogue or a grant) is that name's key:
// "vaults/<vaultID>/<name>", optionally followed by a re-created name
// ("new-<k>", k >= 2, directly after the name; formats §9.3.1), a rotation
// ("v<N>") and a renewal ("gen-<n>"), each at most once. The vaults accept any
// key the caller owns, so this is what stops a name from being pointed at
// another of the caller's keys.
func CheckVaultKeyHandle(vaultID, name, handle string) error {
	base := "vaults/" + vaultID + "/" + name
	if vaultID == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("vault key name %q in vault %q cannot be checked", name, vaultID)
	}
	if handle == base {
		return nil
	}
	if !strings.HasPrefix(handle, base+"/") {
		return fmt.Errorf("the control plane gives handle %q for key %q, which is not that key", handle, name)
	}
	seen := map[string]bool{}
	for i, seg := range strings.Split(strings.TrimPrefix(handle, base+"/"), "/") {
		kind, n := handleSegment(seg)
		switch {
		case kind == "":
			return fmt.Errorf("the control plane gives handle %q for key %q, with an unknown part %q", handle, name, seg)
		case seen[kind]:
			return fmt.Errorf("the control plane gives handle %q for key %q, with %s twice", handle, name, kind)
		case kind == "new-" && (i != 0 || n < 2):
			return fmt.Errorf("the control plane gives handle %q for key %q, with a misplaced %q", handle, name, seg)
		case kind != "new-" && n < 1:
			return fmt.Errorf("the control plane gives handle %q for key %q, with %q", handle, name, seg)
		}
		seen[kind] = true
	}
	return nil
}

// handleSegment reads "new-<k>", "v<N>" or "gen-<n>" (canonical decimal).
func handleSegment(seg string) (string, int) {
	for _, p := range []string{"new-", "gen-", "v"} {
		if !strings.HasPrefix(seg, p) {
			continue
		}
		digits := strings.TrimPrefix(seg, p)
		n, err := strconv.Atoi(digits)
		if err != nil || digits == "" || digits[0] == '0' || strconv.Itoa(n) != digits {
			return "", 0
		}
		return p, n
	}
	return "", 0
}
