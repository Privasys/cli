// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestBillingReads(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/billing/balance":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"enabled": true,
				"data":    map[string]interface{}{"balance": 9_500_000, "frozen": false},
			})
		case "/api/v1/billing/usage":
			if r.URL.Query().Get("since") != "2026-06-01T00:00:00Z" {
				t.Errorf("since not forwarded: %q", r.URL.Query().Get("since"))
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"enabled": true,
				"data":    map[string]interface{}{"total_credits": 500000, "by_resource": []interface{}{}},
			})
		case "/api/v1/billing/ledger":
			if r.URL.Query().Get("limit") != "5" {
				t.Errorf("limit not forwarded: %q", r.URL.Query().Get("limit"))
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false})
		default:
			t.Fatalf("unexpected %s", r.URL.Path)
		}
	})
	defer done()
	ctx := context.Background()

	bal, err := c.BillingBalance(ctx)
	if err != nil || !bal.Enabled || bal.Data["balance"].(float64) != 9_500_000 {
		t.Fatalf("balance: %+v %v", bal, err)
	}
	if _, err := c.BillingUsage(ctx, "2026-06-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	led, err := c.BillingLedger(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if led.Enabled {
		t.Errorf("expected disabled ledger envelope")
	}
}

func TestBillingCheckoutAndPortal(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/v1/billing/checkout/membership":
			json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true, "url": "https://checkout.stripe.com/x"})
		case "/api/v1/billing/checkout/credits":
			json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true, "url": "https://checkout.stripe.com/credits"})
		case "/api/v1/billing/portal":
			json.NewEncoder(w).Encode(map[string]interface{}{"enabled": true, "url": "https://billing.stripe.com/p"})
		default:
			t.Fatalf("unexpected %s", r.URL.Path)
		}
	})
	defer done()
	ctx := context.Background()

	url, enabled, err := c.Checkout(ctx, "membership")
	if err != nil || !enabled || url != "https://checkout.stripe.com/x" {
		t.Fatalf("membership: %q %v %v", url, enabled, err)
	}
	if url, _, _ := c.Checkout(ctx, "credits"); url != "https://checkout.stripe.com/credits" {
		t.Fatalf("credits url: %q", url)
	}
	purl, enabled, err := c.BillingPortal(ctx)
	if err != nil || !enabled || purl != "https://billing.stripe.com/p" {
		t.Fatalf("portal: %q %v %v", purl, enabled, err)
	}
}
