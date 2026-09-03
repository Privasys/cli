// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

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
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: attServer, Token: attToken},
	}, nil
}

func vaultReg(ep string) vault.VaultRegistration {
	return vault.VaultRegistration{ID: ep, Endpoint: ep, Status: "static"}
}

// createWholeKeyOnVault creates a whole (not Shamir-split) key on ONE vault of
// the constellation — single-enclave custody (v1) for operational key types
// (signing / wrapping) whose ops run in-enclave. The platform mints the cnf-bound
// grant and never sees the material.
func createWholeKeyOnVault(ctx context.Context, p VaultCreateParams, material []byte) (*Result, error) {
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
	if _, err := c.CreateKey(ctx, addr.Handle, material, grant); err != nil {
		return nil, fmt.Errorf("create key on %s: %w", ep, err)
	}
	return &Result{
		Handle: addr.Handle, Created: 1, Total: 1, Threshold: 1,
		Exportable: p.Exportable, Thumbprint: cnf, Endpoint: ep,
	}, nil
}

// CreateSigningKeyInVault creates a managed P-256 signing key (single-enclave
// custody): the keypair is generated client-side, the whole PKCS#8 private key is
// created on one vault, and Sign happens in-enclave there.
func CreateSigningKeyInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate p256: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return createWholeKeyOnVault(ctx, p, pkcs8)
}

// CreateAesKeyInVault creates a managed AES-256-GCM wrapping key (single-enclave
// custody): 32 random bytes generated client-side, created whole on one vault;
// Wrap/Unwrap happen in-enclave there, the key never leaves.
func CreateAesKeyInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		return nil, fmt.Errorf("generate aes-256 key: %w", err)
	}
	return createWholeKeyOnVault(ctx, p, material)
}

// WrapInVault encrypts plaintext under an AES-256-GCM key in-enclave (the key
// never leaves), authenticating as the owner. Returns (ciphertext, iv). Tries
// each endpoint until the holder vault responds. iv is optional: nil lets the
// vault generate one (the default); a caller-supplied 12-byte IV serves callers
// whose protocol fixes the nonce (PKCS#11 CKM_AES_GCM) — the caller then owns
// nonce uniqueness per key.
func WrapInVault(ctx context.Context, p VaultOpParams, plaintext, aad, iv []byte) (ciphertext, gotIV []byte, vaultEp string, err error) {
	verify, verr := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if verr != nil {
		return nil, nil, "", verr
	}
	opts := vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify}
	var lastErr error
	for _, ep := range p.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		ct, gotIV, werr := c.Wrap(ctx, p.Handle, plaintext, aad, iv)
		c.Close()
		if werr != nil {
			if strings.Contains(werr.Error(), "not found") {
				continue
			}
			lastErr = werr
			continue
		}
		return ct, gotIV, ep, nil
	}
	return nil, nil, "", fmt.Errorf("no vault could wrap with %q: %v", p.Handle, lastErr)
}

// DestroyKeyInVault deletes a key's material from the constellation,
// authenticating as the owner. It tries every endpoint (a Shamir secret lives on
// all; a single-enclave operational key on one), ignoring "not found", so it is
// idempotent. Returns the endpoints the key was deleted from.
func DestroyKeyInVault(ctx context.Context, p VaultOpParams) (deletedOn []string, err error) {
	verify, verr := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if verr != nil {
		return nil, verr
	}
	opts := vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify}
	var deleted []string
	var lastErr error
	for _, ep := range p.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		derr = c.DeleteKey(ctx, p.Handle)
		c.Close()
		if derr != nil {
			if strings.Contains(derr.Error(), "not found") {
				continue
			}
			lastErr = derr
			continue
		}
		deleted = append(deleted, ep)
	}
	if len(deleted) == 0 && lastErr != nil {
		return nil, fmt.Errorf("delete key material for %q: %v", p.Handle, lastErr)
	}
	return deleted, nil
}

// ReadAuditInVault reads a key's audit log (owner-authenticated; the owner is a
// policy principal). Tries each endpoint until the holder responds.
func ReadAuditInVault(ctx context.Context, p VaultOpParams, limit int) ([]AuditRecord, string, error) {
	verify, verr := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if verr != nil {
		return nil, "", verr
	}
	if limit <= 0 {
		limit = 256
	}
	opts := vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify}
	var lastErr error
	for _, ep := range p.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		entries, _, aerr := c.ReadAuditLog(ctx, p.Handle, 0, uint32(limit))
		c.Close()
		if aerr != nil {
			if strings.Contains(aerr.Error(), "not found") {
				continue
			}
			lastErr = aerr
			continue
		}
		out := make([]AuditRecord, 0, len(entries))
		for _, e := range entries {
			out = append(out, AuditRecord{
				Seq: e.Seq, Ts: e.Ts, Op: e.Op, Caller: e.Caller,
				Decision: fmt.Sprintf("%v", e.Decision), Reason: e.Reason,
			})
		}
		return out, ep, nil
	}
	return nil, "", fmt.Errorf("no vault has audit for %q: %v", p.Handle, lastErr)
}

// UnwrapInVault decrypts ciphertext under an AES-256-GCM key in-enclave.
func UnwrapInVault(ctx context.Context, p VaultOpParams, ciphertext, iv, aad []byte) (plaintext []byte, vaultEp string, err error) {
	verify, verr := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if verr != nil {
		return nil, "", verr
	}
	opts := vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify}
	var lastErr error
	for _, ep := range p.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), opts)
		if derr != nil {
			lastErr = derr
			continue
		}
		pt, uerr := c.Unwrap(ctx, p.Handle, ciphertext, iv, aad)
		c.Close()
		if uerr != nil {
			if strings.Contains(uerr.Error(), "not found") {
				continue
			}
			lastErr = uerr
			continue
		}
		return pt, ep, nil
	}
	return nil, "", fmt.Errorf("no vault could unwrap with %q: %v", p.Handle, lastErr)
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

// SignPrehashInVault signs a 32-byte SHA-256 digest raw (ECDSA-P256, no re-hash)
// — for PKCS#11 CKM_ECDSA / TLS. Mirrors SignInVault but uses the prehash path.
func SignPrehashInVault(ctx context.Context, p VaultOpParams, digest []byte) (*SignResult, error) {
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
		sig, alg, serr := c.SignPrehash(ctx, p.Handle, digest)
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
		TEE:       ratls.TeeTypeSGX,
		MRENCLAVE: mre,
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
		TEE:       ratls.TeeTypeSGX,
		MRENCLAVE: mre,
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
