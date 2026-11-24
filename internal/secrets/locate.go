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

// LocateSecret finds the generation of a user secret that a lookup by name
// uses (see selectGeneration) and the constellation holding it. A secret
// (users/<sub>/<name>) is created straight on the vaults, so no catalogue
// records where it is; after a vault roll, or a renewal that moved it, it is
// no longer on the active one. Every constellation that still serves keys is
// looked at. The result's Handle is the generation chosen, and Warning names
// one passed over. tokenFor gives the owner's bearer for the audience a
// constellation's vaults accept.
func LocateSecret(ctx context.Context, dir Directory, handle string, tokenFor TokenFor, attTok string) (*api.VaultDirectory, *PublicKeyResult, error) {
	cons, err := dir.LiveVaultConstellations(ctx)
	if err != nil || len(cons) == 0 {
		// A control plane without the listing: the active constellation only.
		cons = []api.LiveConstellation{{}}
	}
	var cands []genCandidate
	tokens := map[*api.VaultDirectory]string{}
	var lastErr error
	unreachable := []string{}
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
		tokens[d] = ownerTok
		found, listed := listGenerations(ctx, d, ownerTok, attTok, handle, now)
		if listed {
			cands = append(cands, found...)
			continue
		}
		// A vault that cannot list keys is asked for the name itself, as
		// before generations existed.
		_, ierr := GetPublicKeyInVault(ctx, VaultOpParams{
			Handle: handle, Endpoints: d.Endpoints, MRENCLAVE: d.MRENCLAVE,
			AttServer: d.AttestationServer, AttToken: attTok, OwnerToken: ownerTok,
		})
		switch {
		case ierr == nil:
			cands = append(cands, genCandidate{Handle: handle, Gen: 1, Dir: d})
		case !errors.Is(ierr, ErrKeyNotFound):
			lastErr = ierr
			unreachable = append(unreachable, d.Name)
		}
	}
	chosen, warning, serr := selectGeneration(handle, cands)
	if serr != nil {
		return nil, nil, serr
	}
	if chosen != nil {
		info, ierr := GetPublicKeyInVault(ctx, VaultOpParams{
			Handle: chosen.Handle, Endpoints: chosen.Dir.Endpoints, MRENCLAVE: chosen.Dir.MRENCLAVE,
			AttServer: chosen.Dir.AttestationServer, AttToken: attTok, OwnerToken: tokens[chosen.Dir],
		})
		if ierr != nil {
			return nil, nil, fmt.Errorf("read %s on %s: %w", chosen.Handle, chosen.Dir.Name, ierr)
		}
		info.Handle, info.Warning = chosen.Handle, warning
		return chosen.Dir, info, nil
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
