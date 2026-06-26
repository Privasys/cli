// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build ratls

package secrets

import (
	"context"
	"encoding/hex"
	"fmt"

	ratls "enclave-os-mini/clients/go/ratls"
	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Create mints a key-creation grant for the user and creates a Shamir-split,
// user-owned key across the vault constellation, presenting the holder-of-key
// leaf so the vault's cnf check passes. Returns once at least `Threshold`
// vaults have accepted a share.
func Create(ctx context.Context, p CreateParams) (*Result, error) {
	if len(p.Endpoints) == 0 {
		return nil, fmt.Errorf("no vault endpoints configured")
	}
	if p.Threshold < 1 {
		p.Threshold = 2
	}
	if len(p.Secret) == 0 {
		return nil, fmt.Errorf("empty secret material")
	}

	cert, cnf, err := generateClientCert(p.Sub)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	grant, err := requestGrant(ctx, p, cnf)
	if err != nil {
		return nil, err
	}

	mre, err := hex.DecodeString(p.MRENCLAVE)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
	}
	verify := &ratls.VerificationPolicy{
		TEE:        ratls.TeeTypeSGX,
		MRENCLAVE:  mre,
		ReportData: ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{
			Endpoint: p.AttServer,
			Token:    p.AttToken,
		},
	}

	con := vault.NewStaticConstellation(p.Endpoints, vault.DialOptions{
		ClientCert:  cert,
		VaultPolicy: verify,
	})
	results, _, err := con.CreateKeyShares(ctx, p.Handle, p.Secret, p.Threshold, grant)
	if err != nil {
		return nil, fmt.Errorf("create key shares: %w", err)
	}

	created := 0
	var firstErr error
	for _, r := range results {
		if r.Success {
			created++
		} else if firstErr == nil && r.Err != nil {
			firstErr = r.Err
		}
	}
	res := &Result{
		Handle: p.Handle, Created: created, Total: len(results),
		Threshold: p.Threshold, Exportable: p.Exportable, Thumbprint: cnf,
	}
	if created < p.Threshold {
		return res, fmt.Errorf("only %d of %d vaults accepted the key (need %d): %v",
			created, len(results), p.Threshold, firstErr)
	}
	return res, nil
}
