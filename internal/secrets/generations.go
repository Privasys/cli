// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

// Generations of a user secret.
//
// On a binding v2 vault a secret is renewed into a successor with a new handle
// (the vault copies the policy), so a secret has generations: its first handle
// users/<sub>/<name>, then <that>/v2, /v3 and so on. Every lookup by name
// resolves the newest unexpired generation, so the owner keeps typing the name.

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

var generationSuffix = regexp.MustCompile(`/v([0-9]+)$`)

const maxGeneration = 1_000_000

// generationOf is the generation of handle as one of base's, or 0 when it is
// not one of them. base itself is generation 1.
func generationOf(base, handle string) int {
	if handle == base {
		return 1
	}
	rest, ok := strings.CutPrefix(handle, base)
	if !ok {
		return 0
	}
	m := generationSuffix.FindStringSubmatch(rest)
	if m == nil || m[0] != rest || strings.HasPrefix(m[1], "0") {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	// A bound well past any real renewal count, so the next generation never
	// overflows.
	if err != nil || n < 2 || n > maxGeneration {
		return 0
	}
	return n
}

// GenerationHandle is the handle of generation n of base.
func GenerationHandle(base string, n int) string {
	if n <= 1 {
		return base
	}
	return fmt.Sprintf("%s/v%d", base, n)
}

// checkSecretName refuses a name that would read as a generation of another.
func checkSecretName(handle string) error {
	if generationSuffix.MatchString(handle) {
		return fmt.Errorf("a secret's name may not end in /v<number>: that is how its renewals are named")
	}
	return nil
}

// newestGeneration lists the owner's keys on one constellation and returns the
// newest unexpired generation of base, or "" when it holds none. ok is false
// when no vault answered the listing.
func newestGeneration(ctx context.Context, d *api.VaultDirectory, ownerTok, attTok, base string, now time.Time) (handle string, gen int, ok bool) {
	verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
	if err != nil {
		return "", 0, false
	}
	for _, ep := range d.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
		if derr != nil {
			continue
		}
		keys, lerr := c.ListKeys(ctx)
		c.Close()
		if lerr != nil {
			continue
		}
		for _, k := range keys {
			n := generationOf(base, k.Handle)
			if n == 0 || (k.ExpiresAt > 0 && int64(k.ExpiresAt) <= now.Unix()) {
				continue
			}
			if n > gen {
				handle, gen = k.Handle, n
			}
		}
		return handle, gen, true
	}
	return "", 0, false
}

// GenerationOf is the generation of handle as one of base's (1 for base itself),
// or 0 when it is not one of them.
func GenerationOf(base, handle string) int { return generationOf(base, handle) }
