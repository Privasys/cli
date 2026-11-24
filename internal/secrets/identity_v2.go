// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/json"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// PinnedIdentity is a vault's identity as read over that vault's own RA-TLS
// connection, whose verification pinned the vault's MRENCLAVE. It is the only
// kind of identity a v2 approval accepts, and only ReadPinnedIdentity makes
// one: an identity from the control plane's API, a file or a cache would make
// the member set, and so where an approval is valid, whatever that source says.
type PinnedIdentity struct{ id vault.VaultIdentity }

// ReadPinnedIdentity asks the vault for its identity. The client must have been
// dialled with a VaultPolicy pinning an MRENCLAVE; GetVaultIdentity refuses
// otherwise.
func ReadPinnedIdentity(ctx context.Context, c *vault.Client) (PinnedIdentity, error) {
	id, err := c.GetVaultIdentity(ctx)
	if err != nil {
		return PinnedIdentity{}, err
	}
	return PinnedIdentity{id: id}, nil
}

// MemberID is the vault's member id.
func (p PinnedIdentity) MemberID() string { return p.id.MemberID }

// MarshalJSON relays the vault's answer untouched, for privasys.id and the
// wallet, which verifies the quote.
func (p PinnedIdentity) MarshalJSON() ([]byte, error) { return json.Marshal(p.id) }
