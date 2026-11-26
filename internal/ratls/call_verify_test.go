// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// A call that cannot verify the quote with the attestation server is refused
// before any connection (the address is TEST-NET-1, never dialled).
func TestCallRefusesWithoutQuoteVerification(t *testing.T) {
	for name, p := range map[string]CallParams{
		"no url":   {AttServerTok: "att"},
		"no token": {AttServerURL: "https://as.example/verify"},
		"neither":  {},
	} {
		p.Host, p.ServerName, p.AppType, p.AppToken = "192.0.2.1", "app.example", "container", "owner"
		var out bytes.Buffer
		if _, err := Call(context.Background(), p, &out); !errors.Is(err, ErrNoQuoteVerification) || out.Len() != 0 {
			t.Errorf("%s: err = %v, %d bytes written", name, err, out.Len())
		}
	}
}
