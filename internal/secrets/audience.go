// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"fmt"
	"strings"
)

// AudienceFor finds the audience the vaults at endpoints accept, from the
// live constellation with that MRENCLAVE whose endpoints include all of them.
// No match gives "" (the default audience, as before). Matches that disagree
// are refused rather than guessed. The audience only decides which token is
// asked for: the vaults check it, and the connection stays pinned to
// mrenclave either way.
func AudienceFor(ctx context.Context, dir Directory, endpoints []string, mrenclave string) (string, error) {
	cons, err := dir.LiveVaultConstellations(ctx)
	if err != nil {
		return "", nil
	}
	found, matched := "", false
	for _, c := range cons {
		d, derr := dir.VaultDirectoryAt(ctx, c.ID)
		if derr != nil || !strings.EqualFold(d.MRENCLAVE, mrenclave) || !containsAll(d.Endpoints, endpoints) {
			continue
		}
		if matched && d.OIDCAudience != found {
			return "", fmt.Errorf("the vaults at %s belong to constellations with different audiences (%q, %q)",
				strings.Join(endpoints, ", "), found, d.OIDCAudience)
		}
		found, matched = d.OIDCAudience, true
	}
	return found, nil
}

func containsAll(have, want []string) bool {
	if len(want) == 0 {
		return false
	}
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
