// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"errors"
	"sync"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// runIssuer is the identity provider this run signs in with, set by loadEnv.
var runIssuer struct {
	sync.Mutex
	v string
}

func setRunIssuer(issuer string) {
	runIssuer.Lock()
	runIssuer.v = issuer
	runIssuer.Unlock()
}

// withPollBearers lets an approval wait renew its bearer from the run's own
// sign-in, so a tap that comes late is still collected.
func withPollBearers(ctx context.Context) context.Context {
	return secrets.WithBearerSource(ctx, func(ctx context.Context, audience string) (string, error) {
		runIssuer.Lock()
		issuer := runIssuer.v
		runIssuer.Unlock()
		if issuer == "" {
			return "", errors.New("no issuer for this run")
		}
		if audience == auth.CurrentPlatformAudience() {
			return auth.AccessToken(ctx, issuer)
		}
		return auth.AccessTokenForAudience(ctx, issuer, audience)
	})
}
