// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// VaultDirectory is a constellation's addressing — the pin + attestation server
// + the enabled vault endpoints — from the directory (GET /api/v1/vaults).
// Used to dial the constellation for in-enclave key operations (sign, get-public).
type VaultDirectory struct {
	ID                string
	Name              string
	MRENCLAVE         string
	AttestationServer string
	Endpoints         []string
}

// VaultDirectory fetches the active constellation's addressing.
func (c *Client) VaultDirectory(ctx context.Context) (*VaultDirectory, error) {
	return c.VaultDirectoryAt(ctx, "")
}

// VaultDirectoryAt fetches one constellation's addressing: a key's home, which
// may no longer be the active constellation after a vault roll. An empty id
// means the active one.
func (c *Client) VaultDirectoryAt(ctx context.Context, constellationID string) (*VaultDirectory, error) {
	path := "/api/v1/vaults"
	if constellationID != "" {
		path += "?constellation=" + url.QueryEscape(constellationID)
	}
	var raw json.RawMessage
	if err := c.getJSON(ctx, path, &raw); err != nil {
		return nil, err
	}
	var resp struct {
		Constellation *struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			Mrenclave         string `json:"mrenclave"`
			AttestationServer string `json:"attestation_server"`
		} `json:"constellation"`
		Vaults []struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"vaults"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if resp.Constellation == nil {
		return nil, fmt.Errorf("no active vault constellation is configured")
	}
	d := &VaultDirectory{
		ID:                resp.Constellation.ID,
		Name:              resp.Constellation.Name,
		MRENCLAVE:         resp.Constellation.Mrenclave,
		AttestationServer: resp.Constellation.AttestationServer,
	}
	for _, v := range resp.Vaults {
		d.Endpoints = append(d.Endpoints, fmt.Sprintf("%s:%d", v.Host, v.Port))
	}
	return d, nil
}

// LiveConstellation is a constellation that still serves keys.
type LiveConstellation struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// LiveVaultConstellations lists the constellations that still serve keys, the
// active one first, then the others newest first (GET /api/v1/vaults/constellations).
// A key with no recorded home (a user secret) is looked for in this order.
func (c *Client) LiveVaultConstellations(ctx context.Context) ([]LiveConstellation, error) {
	var resp struct {
		Constellations []LiveConstellation `json:"constellations"`
	}
	if err := c.getJSON(ctx, "/api/v1/vaults/constellations", &resp); err != nil {
		return nil, err
	}
	return resp.Constellations, nil
}
