// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Privasys/cli/internal/config"
)

// PendingDevice persists an in-progress device authorization so a later
// invocation (CLI `auth poll`, or the MCP `auth_poll` tool) can complete it.
// It holds the PKCE verifier + device_code, so it lives in a 0600 file and is
// never returned through any agent-readable channel.
type PendingDevice struct {
	Issuer     string    `json:"issuer"`
	DeviceCode string    `json:"device_code"`
	Verifier   string    `json:"verifier"`
	UserCode   string    `json:"user_code"`
	Interval   int       `json:"interval"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func pendingPath() (string, error) {
	d, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "pending-device.json"), nil
}

// SavePending writes the pending device authorization (0600).
func SavePending(p PendingDevice) error {
	path, err := pendingPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadPending reads the pending device authorization, or an error if none.
func LoadPending() (PendingDevice, error) {
	var p PendingDevice
	path, err := pendingPath()
	if err != nil {
		return p, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("no pending login (run `auth begin` / `auth_begin` first)")
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	return p, nil
}

// RemovePending deletes the pending device authorization (best-effort).
func RemovePending() {
	if path, err := pendingPath(); err == nil {
		_ = os.Remove(path)
	}
}

// SaveUserCredential stores the tokens from a completed user login.
func SaveUserCredential(issuer string, tr *TokenResponse) error {
	cred := &Credential{
		Issuer:          issuer,
		ClientID:        ClientID,
		Subject:         subjectOf(tr.AccessToken),
		Scope:           tr.Scope,
		AccessToken:     tr.AccessToken,
		IDToken:         tr.IDToken,
		RefreshToken:    tr.RefreshToken,
		AccessExpiresAt: time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
	return Save(cred)
}

func subjectOf(token string) string {
	claims, err := Claims(token)
	if err != nil {
		return ""
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}
