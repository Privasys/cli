// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// bearerClaims are the claims pollBearer compares (unverified: the bearer is
// the run's own, and the server checks every token it is sent).
type bearerClaims struct {
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp int64           `json:"exp"`
}

// audience is a single aud, or "" when the token names none or several.
func (c *bearerClaims) audience() string {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil && len(many) == 1 {
		return many[0]
	}
	return ""
}

func tokenClaimsOf(jwt string) (*bearerClaims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("unreadable claims")
	}
	var c bearerClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("unreadable claims")
	}
	return &c, nil
}

// An approval wait can outlast the bearer it started with: the owner may tap
// minutes after the card is sent, and the run's token may already have been
// partway through its life. Each poll therefore asks for a fresh bearer once
// the current one is close to expiry.

// BearerSource returns a current bearer for audience, for the same signed-in
// person as before.
type BearerSource func(ctx context.Context, audience string) (string, error)

type bearerSourceKey struct{}

// WithBearerSource lets approval polls renew their bearer through src.
func WithBearerSource(ctx context.Context, src BearerSource) context.Context {
	return context.WithValue(ctx, bearerSourceKey{}, src)
}

// pollRenewBefore is how long before its expiry a poll's bearer is replaced.
const pollRenewBefore = 90 * time.Second

// pollBearer returns bearer while it has time left, otherwise a fresh bearer
// for the same audience and subject. Anything it cannot confirm leaves the
// current bearer in place, so the poll behaves as it did before.
func pollBearer(ctx context.Context, bearer string) string {
	claims, err := tokenClaimsOf(bearer)
	if err != nil || claims.Exp == 0 || time.Until(time.Unix(claims.Exp, 0)) > pollRenewBefore {
		return bearer
	}
	src, _ := ctx.Value(bearerSourceKey{}).(BearerSource)
	aud := claims.audience()
	if src == nil || aud == "" {
		return bearer
	}
	fresh, err := src(ctx, aud)
	if err != nil || fresh == "" || fresh == bearer {
		return bearer
	}
	next, err := tokenClaimsOf(fresh)
	if err != nil || next.Sub != claims.Sub || next.audience() != aud || next.Exp <= claims.Exp {
		return bearer
	}
	return fresh
}
