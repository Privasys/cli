// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build !ratls

package secrets

import (
	"context"
	"errors"
)

// Create is unavailable without the RA-TLS build (it dials the vault
// constellation over RA-TLS). Released binaries are built with `-tags ratls`.
func Create(ctx context.Context, p CreateParams) (*Result, error) {
	return nil, errors.New("secrets create requires the RA-TLS build of the CLI (use a released binary)")
}

// CreateInVault is unavailable without the RA-TLS build (it dials the vault
// constellation over RA-TLS). Released binaries are built with `-tags ratls`.
func CreateInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	return nil, errors.New("creating a key in a vault requires the RA-TLS build of the CLI (use a released binary)")
}
