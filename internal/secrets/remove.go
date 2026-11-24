// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Privasys/cli/internal/api"
)

// SecretCopy is one generation of a secret held on one constellation.
type SecretCopy struct {
	Handle  string
	Gen     int
	Dir     *api.VaultDirectory
	Expires uint64 // unix seconds, 0 = unknown
}

// Where names the copy and the constellation holding it.
func (c SecretCopy) Where() string {
	if c.Dir == nil {
		return c.Handle
	}
	return c.Handle + " on " + c.Dir.Name
}

// FindSecretCopies lists every copy of a secret the vaults still hold under
// its name: every unexpired generation on every constellation, including
// generations a lookup would not use (on vaults that do not guard generation
// names), since they still hold a value. Unlike LocateSecret it chooses
// nothing. The copies come newest generation first. unreachable names the
// constellations that could not be asked; err is set only when none could.
func FindSecretCopies(ctx context.Context, dir Directory, base string, tokenFor TokenFor, attTok string) (copies []SecretCopy, unreachable []string, err error) {
	cons, lerr := dir.LiveVaultConstellations(ctx)
	if lerr != nil || len(cons) == 0 {
		cons = []api.LiveConstellation{{}}
	}
	var lastErr error
	now := time.Now()
	for _, c := range cons {
		d, derr := dir.VaultDirectoryAt(ctx, c.ID)
		if derr != nil {
			lastErr = derr
			unreachable = append(unreachable, c.Name)
			continue
		}
		ownerTok, terr := tokenFor(ctx, d.OIDCAudience)
		if terr != nil {
			lastErr = terr
			unreachable = append(unreachable, d.Name)
			continue
		}
		found, ignored, listed := listGenerations(ctx, d, ownerTok, attTok, base, now)
		if listed {
			for _, g := range append(found, ignored...) {
				copies = append(copies, SecretCopy{Handle: g.Handle, Gen: g.Gen, Dir: g.Dir, Expires: g.Expires})
			}
			continue
		}
		// A vault that cannot list keys is asked for the bare name.
		_, ierr := GetPublicKeyInVault(ctx, VaultOpParams{
			Handle: base, Endpoints: d.Endpoints, MRENCLAVE: d.MRENCLAVE,
			AttServer: d.AttestationServer, AttToken: attTok, OwnerToken: ownerTok,
		})
		switch {
		case ierr == nil:
			copies = append(copies, SecretCopy{Handle: base, Gen: 1, Dir: d})
		case !errors.Is(ierr, ErrKeyNotFound):
			lastErr = ierr
			unreachable = append(unreachable, d.Name)
		}
	}
	if len(unreachable) == len(cons) && lastErr != nil {
		return nil, unreachable, fmt.Errorf("could not reach any vault constellation to find secret %s: %v", base, lastErr)
	}
	sortNewestFirst(copies)
	return copies, unreachable, nil
}

func sortNewestFirst(copies []SecretCopy) {
	sort.SliceStable(copies, func(i, j int) bool {
		if copies[i].Gen != copies[j].Gen {
			return copies[i].Gen > copies[j].Gen
		}
		return copies[i].Where() < copies[j].Where()
	})
}

// RemoveResult is what happened to one copy.
type RemoveResult struct {
	Copy      SecretCopy
	Deleted   bool
	Attempted bool
	Err       error
}

// RemoveSecretCopies deletes the copies in the order given (newest first),
// each with its own call to del, which asks for that copy's approval. A
// decline stops it: the copies after it are not attempted, and ErrDeclined is
// returned. Any other failure is recorded and the next copy is tried.
func RemoveSecretCopies(ctx context.Context, copies []SecretCopy, del func(context.Context, SecretCopy) error) ([]RemoveResult, error) {
	results := make([]RemoveResult, len(copies))
	for i, c := range copies {
		results[i].Copy = c
	}
	for i, c := range copies {
		results[i].Attempted = true
		err := del(ctx, c)
		if errors.Is(err, ErrDeclined) {
			results[i].Err = err
			return results, fmt.Errorf("%w at %s: it and the %d after it were not deleted", ErrDeclined, c.Where(), len(copies)-i-1)
		}
		results[i].Err = err
		results[i].Deleted = err == nil
	}
	return results, nil
}
