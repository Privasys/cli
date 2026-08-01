// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package secrets implements `secrets create`: an agent (or developer), acting
// for a signed-in user, creates a user-owned key in the vault constellation.
//
// Flow (the key-creation-grants design, CLI/user path):
//  1. Generate an ephemeral RA-TLS client leaf; its SHA-256 thumbprint is the
//     holder-of-key binding (`cnf.x5t#S256`).
//  2. Build the KeyPolicy (owner = Oidc{privasys.id, sub}, owner may export/
//     delete; exportable).
//  3. Ask the IdP for a key-creation grant bound to that policy + thumbprint.
//  4. Generate the secret material.
//  5. Shamir-split it and create one share per vault over mutual RA-TLS,
//     presenting the leaf (so the vault's cnf check passes).
//
// The cert/policy/grant steps are plain Go (here). Step 5 dials the vaults over
// RA-TLS and lives behind the `ratls` build tag (see create_ratls.go); the
// released binary is always built with it.
package secrets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const grantPath = "/vault/key-creation-grant"

// Last-resort fallbacks for the production vault constellation, used only when
// the live directory (GET /api/v1/vaults) is unavailable. The CLI normally
// discovers the active constellation (endpoints + MRENCLAVE + attestation
// server) from the directory — the same source container apps and the SDK use —
// so these need not track every vault cutover. The 2-of-4 SGX constellation
// across Paris + London.
var DefaultEndpoints = []string{
	"141.94.219.130:8443", "141.94.219.130:8444", // Paris
	"198.244.201.58:8443", "198.244.201.58:8444", // London
}

const (
	// Fallback pin (vault-v0.26.0, Paris+London 8443/8444). The directory is the
	// source of truth; this is only used if /api/v1/vaults can't be reached.
	DefaultMRENCLAVE = "d881cff03f1d3be5899fde6605b37fe4e859e5d6c99dd8cbf3bcbc023fe26215"
	DefaultAttServer = "https://as.privasys.org/verify"
)

// CreateParams carries everything needed to create a user secret.
type CreateParams struct {
	Issuer     string   // IdP origin
	Bearer     string   // the user's access token
	Sub        string   // the user's subject (owner of the key)
	Handle     string   // vault key handle, must fall under users/<sub>/
	Secret     []byte   // the key material
	Exportable bool     // whether the owner may export it later
	Endpoints  []string // constellation vault endpoints (host:port)
	Threshold  int      // Shamir k (e.g. 2 of n)
	MRENCLAVE  string   // expected vault MRENCLAVE (hex)
	AttServer  string   // attestation server verify endpoint
	AttToken   string   // aud=attestation-server bearer for quote verification
}

// VaultAddressing is the constellation a vault key is created on, returned by
// the platform alongside the grant.
type VaultAddressing struct {
	Handle    string
	Endpoints []string
	MRENCLAVE string
	AttServer string
	Threshold int
}

// VaultCreateParams creates a key in a user-facing vault using a grant the
// platform mints (the platform authors the policy + catalogues the key; the
// agent creates the material). The platform never sees the material.
type VaultCreateParams struct {
	Sub        string // the key owner's subject
	Secret     []byte // the key material
	Exportable bool
	AttToken   string // aud=attestation-server bearer for quote verification
	// MintGrant asks the platform to mint a grant for a key bound to the agent's
	// holder-of-key cnf, returning the grant and the constellation addressing.
	MintGrant func(ctx context.Context, cnf string) (grant string, addr VaultAddressing, err error)
}

// Result summarises a created secret (no key material).
type Result struct {
	Handle     string `json:"handle"`
	Created    int    `json:"created"` // vaults that accepted a share
	Total      int    `json:"total"`
	Threshold  int    `json:"threshold"`
	Exportable bool   `json:"exportable"`
	Thumbprint string `json:"cnf_x5t_s256"`
	Endpoint   string `json:"endpoint,omitempty"` // single-enclave keys: the holding vault
}

// VaultOpParams addresses an existing key in the constellation for an
// owner-authenticated in-enclave operation (Sign / GetKeyInfo). The owner
// authenticates with their OIDC bearer (the key policy's owner principal); no
// holder-of-key cert is needed once the key exists.
type VaultOpParams struct {
	Handle     string   // the key handle (vaults/<vault-id>/<name>)
	Endpoints  []string // constellation vault endpoints to try (the holder is one of them)
	MRENCLAVE  string   // expected vault MRENCLAVE (hex)
	AttServer  string   // attestation server verify endpoint
	AttToken   string   // aud=attestation-server bearer for quote verification
	OwnerToken string   // the owner's OIDC bearer (aud = the vault audience)
}

// SignResult is an in-enclave signature (the private key never left the vault).
type SignResult struct {
	Signature []byte `json:"-"`
	Alg       string `json:"alg"`
	Vault     string `json:"vault"`
}

// PublicKeyResult is a key's public half (signing keys).
type PublicKeyResult struct {
	KeyType   string `json:"key_type"`
	PublicKey []byte `json:"-"`
	Vault     string `json:"vault"`
}

// AuditRecord is one entry of a key's tamper-evident audit log (who did what).
type AuditRecord struct {
	Seq      uint64 `json:"seq"`
	Ts       uint64 `json:"ts"`
	Op       string `json:"op"`
	Caller   string `json:"caller"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// DigestBytes normalises a pre-hashed sign input to the raw 32-byte SHA-256
// digest: 64 hex chars (the natural CLI/agent form) or the 32 raw bytes.
func DigestBytes(in []byte) ([]byte, error) {
	if len(in) == 64 {
		if b, err := hex.DecodeString(strings.TrimSpace(string(in))); err == nil {
			return b, nil
		}
	}
	if len(in) == 32 {
		return in, nil
	}
	return nil, fmt.Errorf("prehashed sign expects a 32-byte SHA-256 digest (64 hex chars or 32 raw bytes); got %d bytes", len(in))
}

// staticToken is an AuthTokenSource over a fixed bearer (the owner's token).
type staticToken string

func (t staticToken) Token(context.Context) (string, error) { return string(t), nil }

// generateClientCert makes an ephemeral P-256 self-signed leaf used as the
// holder-of-key client certificate. It returns the cert and its base64url
// SHA-256 thumbprint (the `cnf.x5t#S256` value the grant is bound to).
func generateClientCert(sub string) (*tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "privasys-cli secrets " + sub},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if leaf, perr := x509.ParseCertificate(der); perr == nil {
		cert.Leaf = leaf
	}
	return cert, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// stepUpFreshSeconds is how recently the owner must have completed a WebAuthn
// step-up for the vault to honour an ExportKey. Keep it short: export is the
// dangerous read.
const stepUpFreshSeconds = 300

// userKeyPolicyJSON builds the per-key policy as the JSON the vault expects:
// owner = Oidc{privasys.id, sub}; the owner may delete and update; the owner
// principal is immutable. When exportable, ExportKey is its own rule gated on a
// fresh, operation-bound WebAuthn step-up (Condition::OidcStepUp), so a leaked
// owner bearer alone cannot export — the owner must additionally prove a fresh
// wallet assertion bound to this exact export. Hand-built (no SDK import) so
// this stays in the plain-Go path.
func userKeyPolicyJSON(issuer, sub string, exportable bool) json.RawMessage {
	operations := []interface{}{
		map[string]interface{}{
			"ops":        []string{"DeleteKey", "UpdatePolicy"},
			"principals": []string{"Owner"},
		},
	}
	if exportable {
		operations = append(operations, map[string]interface{}{
			"ops":        []string{"ExportKey"},
			"principals": []string{"Owner"},
			"requires": []interface{}{
				map[string]interface{}{
					"OidcStepUp": map[string]interface{}{
						"required_amr":      []string{"webauthn"},
						"operation_bound":   true,
						"fresh_for_seconds": stepUpFreshSeconds,
					},
				},
			},
		})
	}
	policy := map[string]interface{}{
		"version": 1,
		"principals": map[string]interface{}{
			"owner": map[string]interface{}{
				"Oidc": map[string]interface{}{"issuer": issuer, "sub": sub},
			},
		},
		"operations": operations,
		"mutability": map[string]interface{}{"immutable": []string{"Owner"}},
	}
	b, _ := json.Marshal(policy)
	return b
}

// AppDEKGenerationSize is the byte length of the generation prefix the
// enclave-os manager prepends to each app volume-DEK share (its `generationSize`
// const). App-DEK exports set ExportParams.GenerationSize to this.
const AppDEKGenerationSize = 16

// ExportParams carries everything needed to export a user secret. Authn is the
// owner OIDC bearer plus a fresh, operation-bound WebAuthn step-up (driven via
// Assert); the key material is reconstructed from the vault shares in memory and
// returned only to the caller (never logged or printed).
type ExportParams struct {
	Issuer        string           // IdP origin
	Bearer        string           // the user's access token (owner)
	Sub           string           // the user's subject (owner of the key)
	Handle        string           // vault key handle (users/<sub>/...)
	Endpoints     []string         // constellation vault endpoints (host:port)
	Threshold     int              // Shamir k (vaults needed to reconstruct)
	MRENCLAVE     string           // expected vault MRENCLAVE (hex)
	AttServer     string           // attestation server verify endpoint
	AttToken      string           // aud=attestation-server bearer for quote verification
	RequireStepUp bool             // when set, drive an operation-bound WebAuthn step-up
	// Assert produces the WebAuthn step-up assertion in-process (the E2E
	// software-authenticator path). Leave nil for a human owner: the step-up
	// then runs the same wallet-push ceremony `apps versions promote` uses,
	// reporting progress on Out.
	Assert StepUpAssertFunc
	Out    io.Writer     // progress for the human ceremony (defaults to stderr)
	Open   BrowserOpener // optional: open the system-passkey fallback page
	// GenerationSize > 0 means the per-vault material is generation-prefixed
	// (`generation(GenerationSize) || share`), the layout the enclave-os manager
	// uses for app volume DEKs. 0 (default) = raw shares (user secrets).
	GenerationSize int
}

// ExportResult summarises an export (no key material).
type ExportResult struct {
	Handle      string `json:"handle"`
	Retrieved   int    `json:"retrieved"` // vaults that returned a share
	Total       int    `json:"total"`
	Threshold   int    `json:"threshold"`
	Fingerprint string `json:"fingerprint"` // sha256: of the reconstructed key
}

// fingerprint returns a non-reversible identifier for key material so a caller
// can confirm WHICH key was exported without revealing it.
func fingerprint(material []byte) string {
	sum := sha256.Sum256(material)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// grantRequest mirrors the IdP's POST /vault/key-creation-grant body.
type grantRequest struct {
	Scope      string          `json:"scope"`
	KeyType    string          `json:"key_type"`
	Exportable bool            `json:"exportable"`
	Policy     json.RawMessage `json:"policy"`
	CnfX5tS256 string          `json:"cnf_x5t_s256"`
	TTLSeconds int64           `json:"ttl_seconds,omitempty"`
}

// requestGrant asks the IdP for a key-creation grant and returns the JWT.
func requestGrant(ctx context.Context, p CreateParams, cnf string) (string, error) {
	body, _ := json.Marshal(grantRequest{
		Scope:      "users/" + p.Sub,
		KeyType:    "RawShare",
		Exportable: p.Exportable,
		Policy:     userKeyPolicyJSON(p.Issuer, p.Sub, p.Exportable),
		CnfX5tS256: cnf,
		TTLSeconds: 120,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Issuer+grantPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.Bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("key-creation grant %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if out.Grant == "" {
		return "", fmt.Errorf("idp returned no grant")
	}
	return out.Grant, nil
}
