// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"errors"
	"testing"
)

// A tombstone's errors ("key deleted …", formats §9.3) read as gone, and a
// deleted key matches both ErrKeyDeleted and ErrKeyNotFound.
func TestKeyGone(t *testing.T) {
	cases := []struct {
		msg             string
		gone, tombstone bool
	}{
		{"vault error: key deleted at 2026-11-25T10:00:00Z (delete)", true, true},
		{"vault error: key not found", true, false},
		{"caller is not in policy.principals", false, false},
		{"dial: connection refused", false, false},
	}
	for _, c := range cases {
		g, d := keyGone(errors.New(c.msg))
		if g != c.gone || d != c.tombstone {
			t.Errorf("%q: gone %t deleted %t", c.msg, g, d)
		}
	}
	if g, d := keyGone(nil); g || d {
		t.Error("nil read as gone")
	}
	err := deletedErr("users/s/x")
	if !errors.Is(err, ErrKeyDeleted) || !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("deletedErr does not match both: %v", err)
	}
}
