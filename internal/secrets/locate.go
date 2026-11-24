// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Privasys/cli/internal/api"
)

// TokenFor returns the owner's bearer for vaults that accept audience ("" =
// the default vault audience).
type TokenFor func(ctx context.Context, audience string) (string, error)

// Directory is the part of the control-plane client a secret lookup needs.
type Directory interface {
	LiveVaultConstellations(ctx context.Context) ([]api.LiveConstellation, error)
	VaultDirectoryAt(ctx context.Context, constellationID string) (*api.VaultDirectory, error)
}

// LocateSecret finds the newest unexpired generation of a user secret and the
// constellation holding it. A secret (users/<sub>/<name>) is created straight
// on the vaults, so no catalogue records which constellation holds it; after a
// vault roll, or a renewal that moved it, it is no longer on the active one.
// Every constellation that still serves keys is looked at, the active one
// first; the result's Handle is the generation found. tokenFor gives the
// owner's bearer for the audience a constellation's vaults accept.
func LocateSecret(ctx context.Context, dir Directory, handle string, tokenFor TokenFor, attTok string) (*api.VaultDirectory, *PublicKeyResult, error) {
	cons, err := dir.LiveVaultConstellations(ctx)
	if err != nil || len(cons) == 0 {
		// A control plane without the listing: the active constellation only.
		cons = []api.LiveConstellation{{}}
	}
	var (
		bestDir  *api.VaultDirectory
		bestInfo *PublicKeyResult
		bestGen  int
	)
	var lastErr error
	unreachable := []string{}
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
		// The newest generation here; a vault that cannot list keys is asked
		// for the name itself, as before generations existed.
		h, gen, listed := newestGeneration(ctx, d, ownerTok, attTok, handle, time.Now())
		if listed && h == "" {
			continue
		}
		if !listed {
			h, gen = handle, 1
		}
		if gen <= bestGen {
			continue
		}
		info, ierr := GetPublicKeyInVault(ctx, VaultOpParams{
			Handle: h, Endpoints: d.Endpoints, MRENCLAVE: d.MRENCLAVE,
			AttServer: d.AttestationServer, AttToken: attTok, OwnerToken: ownerTok,
		})
		if ierr == nil {
			info.Handle = h
			bestDir, bestInfo, bestGen = d, info, gen
			continue
		}
		if !errors.Is(ierr, ErrKeyNotFound) {
			lastErr = ierr
			unreachable = append(unreachable, d.Name)
		}
	}
	if bestDir != nil {
		return bestDir, bestInfo, nil
	}
	if len(unreachable) == len(cons) && lastErr != nil {
		return nil, nil, fmt.Errorf("could not reach any vault constellation to find secret %s: %v", handle, lastErr)
	}
	if len(unreachable) > 0 {
		return nil, nil, fmt.Errorf("secret %s not found (it may have expired, or never existed); %d constellation(s) did not answer: %v",
			handle, len(unreachable), unreachable)
	}
	return nil, nil, fmt.Errorf("secret %s not found on any constellation: it may have expired, or never existed", handle)
}
