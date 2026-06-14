// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package auth handles CLI authentication: the device authorization grant
// (wallet/agent/passkey), service-account JWT-bearer, credential storage, and
// silent token refresh.
package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/Privasys/cli/internal/config"
)

// keychainService is the OS keychain service name under which secrets are kept.
const keychainService = "privasys-cli"

// ErrNotLoggedIn is returned when no credential exists for an issuer.
var ErrNotLoggedIn = errors.New("not authenticated: run `privasys auth login` or `privasys auth activate-service-account`")

// Credential is the stored authentication state for one issuer.
//
// The long-lived secrets (refresh token, service-account key) are kept in the
// OS keychain when available; the short-lived access/id tokens and metadata
// live in a 0600 file. This split keeps the most sensitive material in the
// keychain while staying under per-item blob limits (e.g. Windows Credential
// Manager ~2.5KB) that a full JWT bundle would blow past.
type Credential struct {
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"client_id,omitempty"`
	Subject         string    `json:"subject,omitempty"`
	Scope           string    `json:"scope,omitempty"`
	AccessToken     string    `json:"access_token,omitempty"`
	IDToken         string    `json:"id_token,omitempty"`
	AccessExpiresAt time.Time `json:"access_expires_at,omitempty"`

	// RefreshToken (user flows) — blanked from the file when kept in keychain.
	RefreshToken      string `json:"refresh_token,omitempty"`
	refreshInKeychain bool

	// ServiceKey (Mode D) — the raw service-key JSON, minted on demand.
	// Blanked from the file when kept in keychain.
	ServiceKey      string `json:"service_key,omitempty"`
	keyInKeychain   bool
	IsServiceKeyAcc bool `json:"is_service_account,omitempty"`
}

func credentialsPath() (string, error) {
	d, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "credentials.json"), nil
}

func loadFile() (map[string]*Credential, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]*Credential{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]*Credential{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func saveFile(m map[string]*Credential) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Save persists a credential, pushing the long-lived secrets to the keychain
// when it is available (falling back to the 0600 file otherwise).
func Save(c *Credential) error {
	m, err := loadFile()
	if err != nil {
		return err
	}

	stored := *c // copy we mutate before writing to the file

	if c.RefreshToken != "" {
		if err := keyring.Set(keychainService, keyName(c.Issuer, "refresh"), c.RefreshToken); err == nil {
			stored.RefreshToken = ""
			stored.refreshInKeychain = true
		}
	}
	if c.ServiceKey != "" {
		if err := keyring.Set(keychainService, keyName(c.Issuer, "sakey"), c.ServiceKey); err == nil {
			stored.ServiceKey = ""
			stored.keyInKeychain = true
		}
	}

	m[c.Issuer] = &stored
	return saveFile(m)
}

// Load returns the credential for an issuer, rehydrating secrets from the
// keychain when they were stored there.
func Load(issuer string) (*Credential, error) {
	m, err := loadFile()
	if err != nil {
		return nil, err
	}
	c, ok := m[issuer]
	if !ok {
		return nil, ErrNotLoggedIn
	}
	if c.refreshInKeychain {
		if v, err := keyring.Get(keychainService, keyName(issuer, "refresh")); err == nil {
			c.RefreshToken = v
		}
	}
	if c.keyInKeychain {
		if v, err := keyring.Get(keychainService, keyName(issuer, "sakey")); err == nil {
			c.ServiceKey = v
		}
	}
	return c, nil
}

// Delete removes a credential and any keychain secrets for the issuer.
func Delete(issuer string) error {
	_ = keyring.Delete(keychainService, keyName(issuer, "refresh"))
	_ = keyring.Delete(keychainService, keyName(issuer, "sakey"))
	m, err := loadFile()
	if err != nil {
		return err
	}
	delete(m, issuer)
	return saveFile(m)
}

// List returns the stored credentials (without rehydrating keychain secrets).
func List() ([]*Credential, error) {
	m, err := loadFile()
	if err != nil {
		return nil, err
	}
	out := make([]*Credential, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	return out, nil
}

func keyName(issuer, kind string) string { return issuer + "|" + kind }

// storedJSON carries the keychain-location flags alongside the credential so
// Load knows where to look. (The flags are unexported on Credential to keep
// them out of the public surface but they must round-trip through JSON.)
type storedJSON struct {
	Credential
	RefreshInKeychain bool `json:"refresh_in_keychain,omitempty"`
	KeyInKeychain     bool `json:"key_in_keychain,omitempty"`
}

func (s storedJSON) toCredential() *Credential {
	c := s.Credential
	c.refreshInKeychain = s.RefreshInKeychain
	c.keyInKeychain = s.KeyInKeychain
	return &c
}

// MarshalJSON/UnmarshalJSON make the unexported keychain flags persist.
func (c *Credential) MarshalJSON() ([]byte, error) {
	type alias Credential
	return json.Marshal(struct {
		*alias
		RefreshInKeychain bool `json:"refresh_in_keychain,omitempty"`
		KeyInKeychain     bool `json:"key_in_keychain,omitempty"`
	}{alias: (*alias)(c), RefreshInKeychain: c.refreshInKeychain, KeyInKeychain: c.keyInKeychain})
}

func (c *Credential) UnmarshalJSON(data []byte) error {
	type alias Credential
	aux := struct {
		*alias
		RefreshInKeychain bool `json:"refresh_in_keychain,omitempty"`
		KeyInKeychain     bool `json:"key_in_keychain,omitempty"`
	}{alias: (*alias)(c)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.refreshInKeychain = aux.RefreshInKeychain
	c.keyInKeychain = aux.KeyInKeychain
	return nil
}
