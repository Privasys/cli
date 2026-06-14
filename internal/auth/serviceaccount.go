// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"time"
)

// PlatformAudience is the default resource-server audience for the
// management-service API.
const PlatformAudience = "privasys-platform"

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// ServiceKey is the on-disk service-account key (same shape the IdP issues).
type ServiceKey struct {
	Type      string `json:"type"`
	KeyID     string `json:"keyId"`
	Key       string `json:"key"` // RSA-2048 private key, PKCS#1 PEM
	UserID    string `json:"userId"`
	AccountID string `json:"accountId"`
}

// ParseServiceKey decodes a service-key.json document.
func ParseServiceKey(data []byte) (*ServiceKey, error) {
	var k ServiceKey
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("invalid service key JSON: %w", err)
	}
	if k.UserID == "" || k.Key == "" || k.KeyID == "" {
		return nil, fmt.Errorf("service key missing required fields (keyId, key, userId)")
	}
	return &k, nil
}

func signAssertion(k *ServiceKey, issuer string) (string, error) {
	block, _ := pem.Decode([]byte(k.Key))
	if block == nil {
		return "", fmt.Errorf("service key: not a PEM block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to PKCS#8 for keys exported in that form.
		if k8, e2 := x509.ParsePKCS8PrivateKey(block.Bytes); e2 == nil {
			if rk, ok := k8.(*rsa.PrivateKey); ok {
				priv = rk
			} else {
				return "", fmt.Errorf("service key: not an RSA key")
			}
		} else {
			return "", fmt.Errorf("service key: parse private key: %w", err)
		}
	}

	now := time.Now()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.KeyID}
	claims := map[string]interface{}{
		"iss": k.UserID,
		"sub": k.UserID,
		"aud": issuer,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(cj)

	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// MintServiceAccountToken exchanges a signed assertion for an access token via
// the JWT-bearer grant.
func MintServiceAccountToken(ctx context.Context, issuer string, k *ServiceKey, audience string) (*TokenResponse, error) {
	if audience == "" {
		audience = PlatformAudience
	}
	assertion, err := signAssertion(k, issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type": {jwtBearerGrantType},
		"assertion":  {assertion},
		"scope":      {"openid audience:" + audience},
	}
	var tr TokenResponse
	if err := postForm(ctx, issuer+"/token", form, &tr); err != nil {
		return nil, err
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("%s: %s", tr.Error, tr.ErrorDescription)
	}
	return &tr, nil
}
