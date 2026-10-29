// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"crypto/rand"
	"fmt"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

// AppKeySize is the length of an app's storage key (the volume DEK the
// enclave-os manager reconstructs; also the input from which the app's backup
// repository password is derived).
const AppKeySize = 32

// CreateAppKeyInVault creates an app's storage key from material its OWNER
// holds (BYOK). Same flow as CreateInVault (the platform authors the policy and
// mints a grant bound to this client's holder-of-key leaf; the material goes
// straight to the vaults), but the shares are written in the layout the
// enclave-os manager reads for app volume keys: one generation id for the whole
// key, prefixed to every vault's share (`generation || share`). An app key
// exported with `apps export-key` is in the same raw form, so either can be
// re-created this way.
func CreateAppKeyInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	if len(p.Secret) != AppKeySize {
		return nil, fmt.Errorf("an app key is %d bytes, got %d", AppKeySize, len(p.Secret))
	}
	cert, cnf, err := generateClientCert(p.Sub)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	grant, addr, err := p.MintGrant(ctx, cnf)
	if err != nil {
		return nil, err
	}
	if len(addr.Endpoints) == 0 {
		return nil, fmt.Errorf("the platform returned no vault endpoints")
	}
	threshold := addr.Threshold
	if threshold < 1 {
		threshold = 2
	}
	verify, err := verifyPolicy(addr.MRENCLAVE, addr.AttServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	shares, err := vault.ShamirSplit(p.Secret, threshold, len(addr.Endpoints))
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}
	generation := make([]byte, AppDEKGenerationSize)
	if _, err := rand.Read(generation); err != nil {
		return nil, fmt.Errorf("generation id: %w", err)
	}
	opts := vault.DialOptions{ClientCert: cert, VaultPolicy: verify}
	res := &Result{Handle: addr.Handle, Total: len(addr.Endpoints), Threshold: threshold,
		Exportable: true, Thumbprint: cnf}
	var firstErr error
	for i, ep := range addr.Endpoints {
		payload := append(append([]byte{}, generation...), vault.ShareToBytes(shares[i])...)
		c, err := vault.Dial(ctx, vaultReg(ep), opts)
		if err == nil {
			_, err = c.CreateKey(ctx, addr.Handle, payload, grant)
			c.Close()
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ep, err)
			}
			continue
		}
		res.Created++
	}
	if res.Created < threshold {
		return res, fmt.Errorf("only %d of %d vaults accepted the key (need %d): %v",
			res.Created, res.Total, threshold, firstErr)
	}
	return res, nil
}
