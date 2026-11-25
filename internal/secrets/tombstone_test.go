// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// A tombstone's errors ("key deleted …", formats §9.3) read as gone, and a
// deleted key matches both ErrKeyDeleted and ErrKeyNotFound. Only the vault's
// own answer counts: a plain error that merely says "not found" does not.
func TestKeyGone(t *testing.T) {
	vaultSaid := func(m string) error { return &vault.ErrVaultError{Message: m} }
	cases := []struct {
		err             error
		gone, tombstone bool
	}{
		{vaultSaid("key deleted at 2026-11-25T10:00:00Z (delete)"), true, true},
		{fmt.Errorf("wrapped: %w", vaultSaid("key not found")), true, false},
		{vaultSaid("caller is not in policy.principals"), false, false},
		{errors.New("vault error: key not found"), false, false},
		{errors.New("dial: connection refused"), false, false},
	}
	for _, c := range cases {
		g, d := keyGone(c.err)
		if g != c.gone || d != c.tombstone {
			t.Errorf("%q: gone %t deleted %t", c.err, g, d)
		}
	}
	if g, d := keyGone(nil); g || d {
		t.Error("nil read as gone")
	}
	err := deletedErr("users/s/x", nil)
	if !errors.Is(err, ErrKeyDeleted) || !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("deletedErr does not match both: %v", err)
	}
	// The vault's record travels with it.
	tomb := &vault.ErrKeyDeleted{Tombstone: vault.KeyTombstone{Handle: "users/s/x", Op: "delete",
		DeletedAt: 1764000000, Successor: "-", ExpiresAt: 1771776000}}
	if g, d := keyGone(fmt.Errorf("wrapped: %w", tomb)); !g || !d {
		t.Fatal("a typed tombstone was not read as deleted")
	}
	de := deletedErr("users/s/x", fmt.Errorf("x: %w", tomb))
	var typed *DeletedError
	if !errors.As(de, &typed) || typed.Tombstone == nil || typed.Tombstone.ExpiresAt != 1771776000 {
		t.Fatalf("the tombstone was lost: %v", de)
	}
	if msg := de.Error(); !strings.Contains(msg, "2025-11-24") || !strings.Contains(msg, "held until 2026-02-22") || strings.Contains(msg, "replaced by") {
		t.Fatalf("message: %s", msg)
	}
}
