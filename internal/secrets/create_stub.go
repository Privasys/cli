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

// CreateSigningKeyInVault, SignInVault and GetPublicKeyInVault dial the vault
// constellation over RA-TLS and are unavailable without the `ratls` build.
func CreateSigningKeyInVault(ctx context.Context, p VaultCreateParams) (*Result, error) {
	return nil, errors.New("creating a signing key requires the RA-TLS build of the CLI (use a released binary)")
}

func SignInVault(ctx context.Context, p VaultOpParams, message []byte) (*SignResult, error) {
	return nil, errors.New("signing requires the RA-TLS build of the CLI (use a released binary)")
}

func GetPublicKeyInVault(ctx context.Context, p VaultOpParams) (*PublicKeyResult, error) {
	return nil, errors.New("reading a public key requires the RA-TLS build of the CLI (use a released binary)")
}
