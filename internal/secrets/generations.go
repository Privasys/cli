// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

// Generations of a user secret.
//
// On a binding v2 vault a secret is renewed into a successor with a new handle
// (the vault copies the policy), so a secret has generations: its first handle
// users/<sub>/<name>, then <that>/gen-2, /gen-3 and so on. A lookup by name
// resolves the newest generation it can trust, so the owner keeps typing the
// name.
//
// Trust is what stops a key planted under a generation's handle from being
// read as the owner's secret. A generation n > 1 is trusted when the vault that
// holds it, advertising CapabilityGenerations over its pinned connection,
// reports it was renewed in place from exactly generation n-1. Such a vault
// creates a .../gen-<n> handle only by renewal, so a missing n-1 (deleted after
// the renewal, or expired) breaks nothing; a present n-1 must be trusted too.
// A generation with no such link (a renewal carried to another constellation)
// is used only when it is the only generation of the name.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

var generationSegment = regexp.MustCompile(`(^|/)gen-([0-9]+)$`)

// maxGeneration bounds generations well past any real renewal count, so the
// next one never overflows.
const maxGeneration = 1_000_000

// generationOf is the generation of handle as one of base's, or 0 when it is
// not one of them. base itself is generation 1.
func generationOf(base, handle string) int {
	if handle == base {
		return 1
	}
	rest, ok := strings.CutPrefix(handle, base+"/gen-")
	if !ok || rest == "" || strings.HasPrefix(rest, "0") {
		return 0
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return 0
		}
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 2 || n > maxGeneration {
		return 0
	}
	return n
}

// GenerationOf is the generation of handle as one of base's (1 for base itself),
// or 0 when it is not one of them.
func GenerationOf(base, handle string) int { return generationOf(base, handle) }

// GenerationHandle is the handle of generation n of base.
func GenerationHandle(base string, n int) string {
	if n <= 1 {
		return base
	}
	return fmt.Sprintf("%s/gen-%d", base, n)
}

// checkSecretName refuses a name whose last segment reads as a generation.
func checkSecretName(handle string) error {
	if generationSegment.MatchString(handle) {
		return fmt.Errorf("a secret's name may not end in gen-<number>: that is how its renewals are named")
	}
	return nil
}

// genCandidate is one generation of a secret, where it was found.
type genCandidate struct {
	Handle  string
	Gen     int
	Linked  string // the generation it was renewed in place from, when trusted
	Dir     *api.VaultDirectory
	Expires uint64
}

// listGenerations reads, over one pinned connection to a vault of d, whether
// the vault advertises generations, the owner's unexpired generations of base,
// and for each n > 1 the handle it was renewed in place from. listed is false
// when no vault answered.
func listGenerations(ctx context.Context, d *api.VaultDirectory, ownerTok, attTok, base string, now time.Time) (cands []genCandidate, listed bool) {
	verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
	if err != nil {
		return nil, false
	}
	for _, ep := range d.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
		if derr != nil {
			continue
		}
		keys, lerr := c.ListKeys(ctx)
		if lerr != nil {
			c.Close()
			continue
		}
		trusted := false
		if id, ierr := ReadPinnedIdentity(ctx, c); ierr == nil {
			trusted = id.Has(vault.CapabilityGenerations)
		}
		for _, k := range keys {
			n := generationOf(base, k.Handle)
			if n == 0 || (k.ExpiresAt > 0 && int64(k.ExpiresAt) <= now.Unix()) {
				continue
			}
			cand := genCandidate{Handle: k.Handle, Gen: n, Dir: d, Expires: k.ExpiresAt}
			if n > 1 && trusted {
				if info, ierr := c.GetKeyInfo(ctx, k.Handle); ierr == nil {
					cand.Linked = info.RenewedInPlaceFrom
				}
			}
			cands = append(cands, cand)
		}
		c.Close()
		return cands, true
	}
	return nil, false
}

// selectGeneration picks the generation a lookup by name uses, from every
// candidate found. warning names a generation that was passed over.
func selectGeneration(base string, cands []genCandidate) (chosen *genCandidate, warning string, err error) {
	byGen := map[int]*genCandidate{}
	for i := range cands {
		if _, dup := byGen[cands[i].Gen]; !dup {
			byGen[cands[i].Gen] = &cands[i]
		}
	}
	memo := map[int]bool{}
	var valid func(n int) bool
	valid = func(n int) bool {
		if v, ok := memo[n]; ok {
			return v
		}
		c := byGen[n]
		ok := n == 1
		if n > 1 && c.Linked == GenerationHandle(base, n-1) {
			// A missing n-1 breaks nothing; a present one must hold too.
			ok = byGen[n-1] == nil || valid(n-1)
		}
		memo[n] = ok
		return ok
	}
	var trusted, unlinked []*genCandidate
	gens := make([]int, 0, len(byGen))
	for n := range byGen {
		gens = append(gens, n)
	}
	sort.Ints(gens)
	for _, n := range gens {
		if valid(n) {
			trusted = append(trusted, byGen[n])
		} else {
			unlinked = append(unlinked, byGen[n])
		}
	}
	switch {
	case len(unlinked) >= 2:
		names := make([]string, len(unlinked))
		for i, u := range unlinked {
			names[i] = u.Handle
		}
		return nil, "", fmt.Errorf("several generations of %s cannot be traced to a renewal (%s): none is used; delete the ones you did not make", base, strings.Join(names, ", "))
	case len(unlinked) == 1 && len(trusted) == 0:
		return unlinked[0], "", nil
	case len(trusted) == 0:
		return nil, "", nil
	}
	chosen = trusted[len(trusted)-1]
	if len(unlinked) == 1 {
		warning = fmt.Sprintf("%s cannot be traced to a renewal, so %s is used; delete %s if you did not make it",
			unlinked[0].Handle, chosen.Handle, unlinked[0].Handle)
	}
	return chosen, warning, nil
}
