// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/Privasys/cli/internal/api"
)

// Directory is the part of the control-plane client a secret lookup needs.
type Directory interface {
	LiveVaultConstellations(ctx context.Context) ([]api.LiveConstellation, error)
	VaultDirectoryAt(ctx context.Context, constellationID string) (*api.VaultDirectory, error)
}

// LocateSecret finds the constellation holding a user secret. A secret
// (users/<sub>/<name>) is created straight on the vaults, so no catalogue
// records which constellation holds it; after a vault roll it is no longer on
// the active one. It is looked for on each constellation that still serves
// keys, the active one first. ownerTok is the owner's bearer.
func LocateSecret(ctx context.Context, dir Directory, handle, ownerTok, attTok string) (*api.VaultDirectory, *PublicKeyResult, error) {
	cons, err := dir.LiveVaultConstellations(ctx)
	if err != nil || len(cons) == 0 {
		// A control plane without the listing: the active constellation only.
		cons = []api.LiveConstellation{{}}
	}
	var lastErr error
	for _, c := range cons {
		d, derr := dir.VaultDirectoryAt(ctx, c.ID)
		if derr != nil {
			lastErr = derr
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
		}
	}
	if lastErr != nil {
		return nil, nil, fmt.Errorf("secret %s not found on any constellation (last error: %v)", handle, lastErr)
	}
	return nil, nil, fmt.Errorf("secret %s not found on any constellation: it may have expired, or never existed", handle)
}
