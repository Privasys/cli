// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// GrantPolicy reads a key-creation grant's policy and owner from its payload,
// without verifying the signature: the vaults verify the grant itself. The
// CLI only needs to know which policy the owner is asked to approve, and it
// checks here that the grant is for the caller and owned by the caller.
func GrantPolicy(grantJWT, callerSub string) (json.RawMessage, error) {
	parts := strings.Split(grantJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("the key-creation grant is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("the key-creation grant's payload is unreadable")
	}
	var claims struct {
		Sub    string          `json:"sub"`
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || len(claims.Policy) == 0 {
		return nil, errors.New("the key-creation grant carries no policy")
	}
	if callerSub == "" || claims.Sub != callerSub {
		return nil, fmt.Errorf("the key-creation grant is for %q, not the caller", claims.Sub)
	}
	var owner struct {
		Principals struct {
			Owner struct {
				Oidc *struct {
					Sub string `json:"sub"`
				} `json:"Oidc"`
			} `json:"owner"`
		} `json:"principals"`
	}
	if err := json.Unmarshal(claims.Policy, &owner); err != nil || owner.Principals.Owner.Oidc == nil ||
		owner.Principals.Owner.Oidc.Sub != callerSub {
		return nil, errors.New("the key-creation grant's policy is not owned by the caller")
	}
	return claims.Policy, nil
}
