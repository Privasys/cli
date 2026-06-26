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
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

const grantPath = "/vault/key-creation-grant"

// Defaults for the production vault constellation (see infrastructure.md): the
// 2-of-4 SGX constellation across Paris + London, its current MRENCLAVE, and
// the attestation server. Override per-invocation when the vault is upgraded.
var DefaultEndpoints = []string{
	"141.94.219.130:8443", "141.94.219.130:8444", // Paris
	"198.244.201.58:8443", "198.244.201.58:8444", // London
}

const (
	DefaultMRENCLAVE = "7f45fa40256be86a6faf9b2b03ffa69984e8b9d8e4e016614d81a31221cbfcb2"
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

// Result summarises a created secret (no key material).
type Result struct {
	Handle     string `json:"handle"`
	Created    int    `json:"created"` // vaults that accepted a share
	Total      int    `json:"total"`
	Threshold  int    `json:"threshold"`
	Exportable bool   `json:"exportable"`
	Thumbprint string `json:"cnf_x5t_s256"`
}

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

// userKeyPolicyJSON builds the per-key policy as the JSON the vault expects:
// owner = Oidc{privasys.id, sub}; the owner may export, delete and update; the
// owner principal is immutable. Hand-built (no SDK import) so this stays in the
// plain-Go path.
func userKeyPolicyJSON(issuer, sub string, exportable bool) json.RawMessage {
	ops := []string{"DeleteKey", "UpdatePolicy"}
	if exportable {
		ops = append([]string{"ExportKey"}, ops...)
	}
	policy := map[string]interface{}{
		"version": 1,
		"principals": map[string]interface{}{
			"owner": map[string]interface{}{
				"Oidc": map[string]interface{}{"issuer": issuer, "sub": sub},
			},
		},
		"operations": []interface{}{
			map[string]interface{}{"ops": ops, "principals": []string{"Owner"}},
		},
		"mutability": map[string]interface{}{"immutable": []string{"Owner"}},
	}
	b, _ := json.Marshal(policy)
	return b
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
