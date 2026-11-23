// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"testing"
	"time"
)

func TestExpiryCell(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in, want string
	}{
		{"", "-"},
		{"not a date", "not a date"},
		{"2027-02-21T12:00:00Z", "2027-02-21 (90 days)"},
		{"2027-02-21T11:59:00Z", "2027-02-21 (90 days)"}, // just created
		{"2026-12-13T12:00:00Z", "2026-12-13 (20 days, renew)"},
		{"2026-11-23T20:00:00Z", "2026-11-23 (today, renew now)"},
		{"2026-11-22T12:00:00Z", "2026-11-22 (expired)"},
	} {
		if got := expiryCell(tc.in, now); got != tc.want {
			t.Errorf("expiryCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
