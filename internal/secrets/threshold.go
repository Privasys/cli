// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"fmt"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

// ThresholdKeyType is the vault key type of a threshold Ed25519 key.
const ThresholdKeyType = "FrostEd25519"

// CreateThresholdKeyInVault creates a threshold Ed25519 key (FROST) across
// every vault of the constellation by distributed key generation: no vault,
// and not this CLI, ever holds the key. threshold is how many vaults must
// sign together (0 = the constellation's own threshold). Returns the result
// and the 32-byte Ed25519 public key.
func CreateThresholdKeyInVault(ctx context.Context, p VaultCreateParams, threshold int) (*Result, []byte, error) {
	cert, cnf, err := generateClientCert(p.Sub)
	if err != nil {
		return nil, nil, fmt.Errorf("client cert: %w", err)
	}
	grant, addr, err := p.MintGrant(ctx, cnf)
	if err != nil {
		return nil, nil, err
	}
	n := len(addr.Endpoints)
	if n < 2 {
		return nil, nil, fmt.Errorf("a threshold key needs at least 2 vaults; the constellation has %d", n)
	}
	if threshold == 0 {
		threshold = addr.Threshold
	}
	if threshold < 2 {
		threshold = 2
	}
	if threshold > n {
		return nil, nil, fmt.Errorf("threshold %d is more than the constellation's %d vaults", threshold, n)
	}
	verify, err := verifyPolicy(addr.MRENCLAVE, addr.AttServer, p.AttToken)
	if err != nil {
		return nil, nil, err
	}
	con := vault.NewStaticConstellation(addr.Endpoints, vault.DialOptions{ClientCert: cert, VaultPolicy: verify})
	key, err := con.CreateThresholdKey(ctx, addr.Handle, grant, threshold)
	if err != nil {
		return nil, nil, err
	}
	return &Result{
		Handle: key.Handle, Created: n, Total: n, Threshold: threshold,
		Exportable: false, Thumbprint: cnf,
	}, key.PublicKey, nil
}

// SignThresholdInVault signs message with a threshold Ed25519 key: every
// reachable vault of its constellation is asked, each checks the key's
// policy against the owner's bearer, and the signature is aggregated and
// verified by one of them.
func SignThresholdInVault(ctx context.Context, p VaultOpParams, message []byte) (*SignResult, error) {
	verify, err := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	con := vault.NewStaticConstellation(p.Endpoints, vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify})
	sig, alg, err := con.SignThreshold(ctx, p.Handle, message, 0)
	if err != nil {
		return nil, fmt.Errorf("threshold sign %q: %w", p.Handle, err)
	}
	return &SignResult{Signature: sig, Alg: alg, Vault: fmt.Sprintf("%d vaults", len(p.Endpoints))}, nil
}
