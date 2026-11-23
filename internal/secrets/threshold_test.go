// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestNoVaultCouldSignNamesAMissingKey(t *testing.T) {
	if e := noVaultCouldSign("h", nil).Error(); !strings.Contains(e, "not found") || strings.Contains(e, "<nil>") {
		t.Fatalf("got %q", e)
	}
	if e := noVaultCouldSign("h", errors.New("boom")).Error(); !strings.Contains(e, "boom") {
		t.Fatalf("got %q", e)
	}
}
