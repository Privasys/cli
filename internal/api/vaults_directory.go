// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// VaultDirectory is the active constellation's addressing — the pin + attestation
// server + the enabled vault endpoints — from the directory (GET /api/v1/vaults).
// Used to dial the constellation for in-enclave key operations (sign, get-public).
type VaultDirectory struct {
	MRENCLAVE         string
	AttestationServer string
	Endpoints         []string
}

// VaultDirectory fetches the active constellation's addressing.
func (c *Client) VaultDirectory(ctx context.Context) (*VaultDirectory, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/api/v1/vaults", &raw); err != nil {
		return nil, err
	}
	var resp struct {
		Constellation *struct {
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
		MRENCLAVE:         resp.Constellation.Mrenclave,
		AttestationServer: resp.Constellation.AttestationServer,
	}
	for _, v := range resp.Vaults {
		d.Endpoints = append(d.Endpoints, fmt.Sprintf("%s:%d", v.Host, v.Port))
	}
	return d, nil
}
