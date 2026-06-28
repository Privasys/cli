// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build ratls

package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	ratls "enclave-os-mini/clients/go/ratls"
	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

// verifyPolicy builds the RA-TLS verification policy for a vault dial from the
// constellation addressing (mrenclave pin + attestation server + token).
func verifyPolicy(mrenclaveHex, attServer, attToken string) (*ratls.VerificationPolicy, error) {
	mre, err := hex.DecodeString(mrenclaveHex)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
	}
	return &ratls.VerificationPolicy{
		TEE:               ratls.TeeTypeSGX,
		MRENCLAVE:         mre,
		ReportData:        ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: attServer, Token: attToken},
	}, nil
}

func vaultReg(ep string) vault.VaultRegistration {
	return vault.VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}
}

// CreateSigningKeyInVault creates a managed P-256 signing key in a user vault.
// Single-enclave custody (v1): the whole PKCS#8 private key is created on ONE
// vault of the constellation; Sign happens in-enclave there, the key never
// leaves. The keypair is generated client-side; the platform mints the cnf-bound
// grant and never sees the material.
func CreateSigningKeyInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate p256: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
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
	verify, err := verifyPolicy(addr.MRENCLAVE, addr.AttServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	ep := addr.Endpoints[0] // single-enclave: the first (deterministic) vault holds it
	c, err := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{ClientCert: cert, VaultPolicy: verify})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", ep, err)
	}
	defer c.Close()
	if _, err := c.CreateKey(ctx, addr.Handle, pkcs8, grant); err != nil {
		return nil, fmt.Errorf("create signing key on %s: %w", ep, err)
	}
	return &Result{
		Handle: addr.Handle, Created: 1, Total: 1, Threshold: 1,
		Exportable: p.Exportable, Thumbprint: cnf, Endpoint: ep,
	}, nil
}

// SignInVault produces an in-enclave ECDSA-P256-SHA256 signature, authenticating
// as the key owner (OIDC bearer). It tries each constellation endpoint until the
// holder vault signs (single-enclave: exactly one holds the key).
func SignInVault(ctx context.Context, p VaultOpParams, message []byte) (*SignResult, error) {
	verify, err := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	opts := vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify}
	var lastErr error
	for _, ep := range p.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		sig, alg, serr := c.Sign(ctx, p.Handle, message)
		c.Close()
		if serr != nil {
			if strings.Contains(serr.Error(), "not found") {
				continue // not the holder vault
			}
			lastErr = serr
			continue
		}
		return &SignResult{Signature: sig, Alg: alg, Vault: ep}, nil
	}
	return nil, fmt.Errorf("no vault could sign %q: %v", p.Handle, lastErr)
}

// GetPublicKeyInVault returns a key's public half + type, trying each endpoint
// until the holder responds.
func GetPublicKeyInVault(ctx context.Context, p VaultOpParams) (*PublicKeyResult, error) {
	verify, err := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	opts := vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify}
	var lastErr error
	for _, ep := range p.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		info, ierr := c.GetKeyInfo(ctx, p.Handle)
		c.Close()
		if ierr != nil {
			if strings.Contains(ierr.Error(), "not found") {
				continue
			}
			lastErr = ierr
			continue
		}
		return &PublicKeyResult{KeyType: string(info.KeyType), PublicKey: info.PublicKey, Vault: ep}, nil
	}
	return nil, fmt.Errorf("no vault has key %q: %v", p.Handle, lastErr)
}

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

// CreateInVault creates a Shamir-split key in a user-facing vault. The platform
// authors the policy, catalogues the key, and mints a grant bound to the agent's
// holder-of-key leaf; this then creates the material directly on the
// constellation. The platform never sees the material.
func CreateInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	if len(p.Secret) == 0 {
		return nil, fmt.Errorf("empty secret material")
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
	mre, err := hex.DecodeString(addr.MRENCLAVE)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vault mrenclave must be 32 bytes of hex")
	}
	verify := &ratls.VerificationPolicy{
		TEE:        ratls.TeeTypeSGX,
		MRENCLAVE:  mre,
		ReportData: ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{
			Endpoint: addr.AttServer,
			Token:    p.AttToken,
		},
	}
	con := vault.NewStaticConstellation(addr.Endpoints, vault.DialOptions{
		ClientCert:  cert,
		VaultPolicy: verify,
	})
	results, _, err := con.CreateKeyShares(ctx, addr.Handle, p.Secret, threshold, grant)
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
		Handle: addr.Handle, Created: created, Total: len(results),
		Threshold: threshold, Exportable: p.Exportable, Thumbprint: cnf,
	}
	if created < threshold {
		return res, fmt.Errorf("only %d of %d vaults accepted the key (need %d): %v",
			created, len(results), threshold, firstErr)
	}
	return res, nil
}
