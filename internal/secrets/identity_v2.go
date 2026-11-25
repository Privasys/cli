// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// ConstellationIdentities reads every member's identity, each over its own
// connection pinned to mrenclave, and checks the members agree: one build, one
// billing configuration, distinct member ids. The pin is the constellation's
// MRENCLAVE as the control plane reports it.
func ConstellationIdentities(ctx context.Context, endpoints []string, mrenclave, attServer, attToken string) ([]PinnedIdentity, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("the constellation has no vaults")
	}
	verify, err := verifyPolicy(mrenclave, attServer, attToken)
	if err != nil {
		return nil, err
	}
	ids := make([]PinnedIdentity, 0, len(endpoints))
	seen := map[string]string{}
	for _, ep := range endpoints {
		c, err := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ep, err)
		}
		id, err := ReadPinnedIdentity(ctx, c)
		c.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ep, err)
		}
		if prev, dup := seen[id.MemberID()]; dup {
			return nil, fmt.Errorf("%s and %s report the same member id", prev, ep)
		}
		seen[id.MemberID()] = ep
		if len(ids) > 0 && id.id.BillingID != ids[0].id.BillingID {
			return nil, fmt.Errorf("%s is under another billing configuration than %s", ep, endpoints[0])
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// BillingID is the vault's billing configuration id.
func (p PinnedIdentity) BillingID() string { return p.id.BillingID }

// memberIDs is the member id of each identity.
func memberIDs(ids []PinnedIdentity) []string {
	m := make([]string, len(ids))
	for i, id := range ids {
		m[i] = id.MemberID()
	}
	return m
}

// Has says whether the vault advertises capability, as read over its pinned
// connection.
func (p PinnedIdentity) Has(capability string) bool { return p.id.Has(capability) }

// Capabilities are the features the vault advertises, as read over its pinned
// connection.
func (p PinnedIdentity) Capabilities() []string { return append([]string(nil), p.id.Capabilities...) }

// MemberIDs is the member id of each identity.
func MemberIDs(ids []PinnedIdentity) []string { return memberIDs(ids) }
