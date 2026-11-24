// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	pathpkg "path"
	"strings"
)

// VaultBearerHeader carries the token the control plane forwards to the vaults
// when the platform's audience is not the vaults' (the test platform). The
// control plane accepts it only for the same account as Authorization.
const VaultBearerHeader = "X-Privasys-Vault-Bearer"

// SetVaultBearer makes the client attach bearer's token, on the routes where
// the control plane calls the vaults with the caller's own token, and only
// there: the token is valid on the vaults' platform too, so it goes no further
// than it must. A bearer that returns "" attaches nothing.
func (c *Client) SetVaultBearer(bearer func(ctx context.Context) (string, error)) {
	base := c.HTTP.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.HTTP.Transport = &vaultBearerTransport{base: base, bearer: bearer}
}

type vaultBearerTransport struct {
	base   http.RoundTripper
	bearer func(ctx context.Context) (string, error)
}

func (t *vaultBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !forwardsToVaults(req.URL.Path) {
		return t.base.RoundTrip(req)
	}
	tok, err := t.bearer(req.Context())
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return t.base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set(VaultBearerHeader, tok)
	return t.base.RoundTrip(r)
}

// forwardsToVaults lists the control plane's routes that act on the vaults:
// an app version's stage, promote, pending, revoke and key rotation, the app
// policy, measurement retirement, data keys and backup restores.
func forwardsToVaults(p string) bool {
	path := pathpkg.Clean(p)
	if path != strings.TrimSuffix(p, "/") || !strings.HasPrefix(path, "/api/v1/") {
		return false
	}
	switch {
	case strings.Contains(path, "/versions/"),
		strings.Contains(path, "/data-key"),
		strings.HasSuffix(path, "/policy"),
		strings.HasSuffix(path, "/retire-measurement"),
		strings.Contains(path, "/restore"):
		return true
	}
	return false
}
