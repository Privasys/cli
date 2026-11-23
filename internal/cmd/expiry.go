// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"fmt"
	"math"
	"time"
)

// renewWithinDays is when a key's expiry starts to warrant attention: the
// platform renews its own keys at 60 days of a 90-day life, and an owner
// should renew theirs by then too.
const renewWithinDays = 30

// expiryCell renders a key's expiry (RFC 3339) for a table: the date and the
// days left, a renewal prompt inside the last 30 days, and "expired" once past.
// The vaults extend no key's life; a long-lived key needs renewing before then.
func expiryCell(expiresAt string, now time.Time) string {
	if expiresAt == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return expiresAt
	}
	date := t.UTC().Format("2006-01-02")
	left := t.Sub(now)
	if left <= 0 {
		return date + " (expired)"
	}
	days := int(math.Round(left.Hours() / 24))
	switch {
	case days < 1:
		return date + " (today, renew now)"
	case days <= renewWithinDays:
		return fmt.Sprintf("%s (%d days, renew)", date, days)
	default:
		return fmt.Sprintf("%s (%d days)", date, days)
	}
}
