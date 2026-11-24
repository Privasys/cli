// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"fmt"

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

// LocateSecret finds the constellation holding a user secret. A secret
// (users/<sub>/<name>) is created straight on the vaults, so no catalogue
// records which constellation holds it; after a vault roll it is no longer on
// the active one. It is looked for on each constellation that still serves
// keys, the active one first. tokenFor gives the owner's bearer for the
// audience a constellation's vaults accept.
func LocateSecret(ctx context.Context, dir Directory, handle string, tokenFor TokenFor, attTok string) (*api.VaultDirectory, *PublicKeyResult, error) {
	cons, err := dir.LiveVaultConstellations(ctx)
	if err != nil || len(cons) == 0 {
		// A control plane without the listing: the active constellation only.
		cons = []api.LiveConstellation{{}}
	}
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
		info, ierr := GetPublicKeyInVault(ctx, VaultOpParams{
			Handle: handle, Endpoints: d.Endpoints, MRENCLAVE: d.MRENCLAVE,
			AttServer: d.AttestationServer, AttToken: attTok, OwnerToken: ownerTok,
		})
		if ierr == nil {
			return d, info, nil
		}
		if !errors.Is(ierr, ErrKeyNotFound) {
			lastErr = ierr
			unreachable = append(unreachable, d.Name)
		}
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
