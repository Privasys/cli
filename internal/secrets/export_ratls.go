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

// Export retrieves a user-owned, Shamir-split secret from the vault
// constellation and reconstructs it in memory. The owner authenticates with
// their OIDC bearer plus a fresh, operation-bound WebAuthn step-up (driven via
// p.Assert); each vault returns only its share, and the whole key is
// reassembled here and returned to the caller. The material is never logged.
func Export(ctx context.Context, p ExportParams) ([]byte, *ExportResult, error) {
	if len(p.Endpoints) == 0 {
		return nil, nil, fmt.Errorf("no vault endpoints configured")
	}
	if p.Threshold < 2 {
		p.Threshold = 2
	}
	mre, err := hex.DecodeString(p.MRENCLAVE)
	if err != nil || len(mre) != 32 {
		return nil, nil, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
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

	// The owner authenticates with their bearer; when the key's policy gates
	// ExportKey on a WebAuthn step-up, swap in a fresh, operation-bound step-up
	// token (which also carries the owner sub, so it satisfies the owner
	// principal AND the OidcStepUp condition in one token).
	authTok := p.Bearer
	if p.RequireStepUp {
		// Read the key's current policy_version (a read; the owner bearer
		// suffices) so the step-up token binds the right version.
		reg := vault.VaultRegistration{ID: p.Endpoints[0], Endpoint: p.Endpoints[0], Status: "static"}
		c, err := vault.Dial(ctx, reg, vault.DialOptions{
			VaultPolicy: verify,
			AuthToken:   vault.StaticToken(p.Bearer),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("dial vault for key info: %w", err)
		}
		info, err := c.GetKeyInfo(ctx, p.Handle)
		c.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("get key info: %w", err)
		}
		stepTok, err := requestExportStepUp(ctx, p.Issuer, p.Bearer, p.Handle, info.PolicyVersion, p.Assert)
		if err != nil {
			return nil, nil, err
		}
		authTok = stepTok
	}

	// Export shares as the owner and reconstruct.
	con := vault.NewStaticConstellation(p.Endpoints, vault.DialOptions{
		VaultPolicy: verify,
		AuthToken:   vault.StaticToken(authTok),
	})
	secret, results, err := con.ExportKeyShares(ctx, p.Handle, p.Threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("export key shares: %w", err)
	}
	retrieved := 0
	for _, r := range results {
		if r.Success {
			retrieved++
		}
	}
	res := &ExportResult{
		Handle: p.Handle, Retrieved: retrieved, Total: len(results),
		Threshold: p.Threshold, Fingerprint: fingerprint(secret),
	}
	return secret, res, nil
}
