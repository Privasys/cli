// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"errors"
	"testing"

	"github.com/Privasys/cli/internal/ratls"
)

func TestExitCodeOfARefusalIsGeneric(t *testing.T) {
	refused := ratls.Refused("the manager's attestation failed, refusing to send anything: %w",
		errors.New("expected OID 1.3 (Enclave Instance ID) not found in certificate"))
	if got := exitCode(refused); got != 1 {
		t.Errorf("a refusal quoting \"not found\" exits %d, want 1", got)
	}
	if got := exitCode(errors.New("app not found")); got != 5 {
		t.Errorf("a missing resource exits %d, want 5", got)
	}
}
