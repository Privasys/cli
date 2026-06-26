// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build !ratls

package secrets

import (
	"context"
	"errors"
)

// Export is unavailable without the RA-TLS build (it dials the vault
// constellation over RA-TLS). Released binaries are built with `-tags ratls`.
func Export(ctx context.Context, p ExportParams) ([]byte, *ExportResult, error) {
	return nil, nil, errors.New("secrets export requires the RA-TLS build of the CLI (use a released binary)")
}
