// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// BillingResult mirrors the management-service {enabled, data?} envelope used
// for credit-ledger reads. When billing is not configured, Enabled is false.
type BillingResult struct {
	Enabled bool                   `json:"enabled"`
	Data    map[string]interface{} `json:"data"`
}

func (c *Client) billingGet(ctx context.Context, path string) (*BillingResult, error) {
	var out BillingResult
	if err := c.getJSON(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// BillingBalance returns the account's credit balance.
func (c *Client) BillingBalance(ctx context.Context) (*BillingResult, error) {
	return c.billingGet(ctx, "/api/v1/billing/balance")
}

// BillingUsage returns the usage rollup, optionally since an RFC3339 time.
func (c *Client) BillingUsage(ctx context.Context, since string) (*BillingResult, error) {
	path := "/api/v1/billing/usage"
	if since != "" {
		path += "?since=" + url.QueryEscape(since)
	}
	return c.billingGet(ctx, path)
}

// BillingLedger returns the credit-ledger history, optionally limited.
func (c *Client) BillingLedger(ctx context.Context, limit int) (*BillingResult, error) {
	path := "/api/v1/billing/ledger"
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}
	return c.billingGet(ctx, path)
}

// BillingSubscription returns the membership subscription state.
func (c *Client) BillingSubscription(ctx context.Context) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := c.getJSON(ctx, "/api/v1/billing/subscription", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Checkout starts a Stripe Checkout session and returns its URL. kind is
// "membership" or "credits".
func (c *Client) Checkout(ctx context.Context, kind string) (string, bool, error) {
	var out struct {
		Enabled bool   `json:"enabled"`
		URL     string `json:"url"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/billing/checkout/"+kind, map[string]interface{}{}, &out); err != nil {
		return "", false, err
	}
	return out.URL, out.Enabled, nil
}

// BillingPortal returns a Stripe Customer Portal URL.
func (c *Client) BillingPortal(ctx context.Context) (string, bool, error) {
	var out struct {
		Enabled bool   `json:"enabled"`
		URL     string `json:"url"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/billing/portal", map[string]interface{}{}, &out); err != nil {
		return "", false, err
	}
	return out.URL, out.Enabled, nil
}
