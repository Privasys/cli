// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config manages the CLI's on-disk configuration: named
// configurations (profiles, like gcloud) plus env-var overrides. It holds
// only non-secret settings; tokens live in the auth package's credential
// store (OS keychain).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Defaults for a fresh configuration.
const (
	DefaultEndpoint = "https://api.developer.privasys.org"
	DefaultIssuer   = "https://privasys.id"
	DefaultFormat   = "table"
	defaultName     = "default"

	// TestEndpoint is the Privasys test/dev platform API, selected with the
	// global --test flag. Auth still goes through the production issuer
	// (privasys.id), so only the platform endpoint differs.
	TestEndpoint = "https://api.developer.test.privasys.org"
)

// Configuration is a single named profile.
type Configuration struct {
	Endpoint string `yaml:"endpoint"`
	Issuer   string `yaml:"issuer"`
	Account  string `yaml:"account,omitempty"`
	Format   string `yaml:"format,omitempty"`
}

// File is the whole config document.
type File struct {
	Current        string                    `yaml:"current"`
	Configurations map[string]*Configuration `yaml:"configurations"`

	path string
}

// Dir returns the CLI config directory (~/.privasys), creating it if needed.
func Dir() (string, error) {
	if d := os.Getenv("PRIVASYS_CONFIG_DIR"); d != "" {
		return d, os.MkdirAll(d, 0o700)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".privasys")
	return d, os.MkdirAll(d, 0o700)
}

func configPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.yaml"), nil
}

// Load reads the config file, returning a default document when none exists.
func Load() (*File, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	f := &File{path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		f.Current = defaultName
		f.Configurations = map[string]*Configuration{
			defaultName: {Endpoint: DefaultEndpoint, Issuer: DefaultIssuer, Format: DefaultFormat},
		}
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	f.path = path
	if f.Configurations == nil {
		f.Configurations = map[string]*Configuration{}
	}
	if f.Current == "" {
		f.Current = defaultName
	}
	if _, ok := f.Configurations[f.Current]; !ok {
		f.Configurations[f.Current] = &Configuration{Endpoint: DefaultEndpoint, Issuer: DefaultIssuer, Format: DefaultFormat}
	}
	return f, nil
}

// Save writes the config file with 0600 permissions.
func (f *File) Save() error {
	data, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	return os.WriteFile(f.path, data, 0o600)
}

// Active returns the current configuration, applying env-var overrides
// (PRIVASYS_ENDPOINT, PRIVASYS_ISSUER, PRIVASYS_ACCOUNT, PRIVASYS_FORMAT).
// Env overrides do not mutate the saved file.
func (f *File) Active() *Configuration {
	base := f.Configurations[f.Current]
	if base == nil {
		base = &Configuration{Endpoint: DefaultEndpoint, Issuer: DefaultIssuer, Format: DefaultFormat}
	}
	c := *base // copy
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	if c.Issuer == "" {
		c.Issuer = DefaultIssuer
	}
	if c.Format == "" {
		c.Format = DefaultFormat
	}
	if v := os.Getenv("PRIVASYS_ENDPOINT"); v != "" {
		c.Endpoint = v
	}
	if v := os.Getenv("PRIVASYS_ISSUER"); v != "" {
		c.Issuer = v
	}
	if v := os.Getenv("PRIVASYS_ACCOUNT"); v != "" {
		c.Account = v
	}
	if v := os.Getenv("PRIVASYS_FORMAT"); v != "" {
		c.Format = v
	}
	return &c
}

// Set updates a key on the current configuration. Returns the persisted value.
func (f *File) Set(key, value string) error {
	c := f.Configurations[f.Current]
	if c == nil {
		c = &Configuration{}
		f.Configurations[f.Current] = c
	}
	switch strings.ToLower(key) {
	case "endpoint":
		c.Endpoint = value
	case "issuer":
		c.Issuer = value
	case "account":
		c.Account = value
	case "format":
		if value != "table" && value != "json" && value != "yaml" {
			return fmt.Errorf("format must be one of table|json|yaml")
		}
		c.Format = value
	default:
		return fmt.Errorf("unknown key %q (valid: endpoint, issuer, account, format)", key)
	}
	return f.Save()
}

// Get reads a key from the active (env-overridden) configuration.
func (f *File) Get(key string) (string, error) {
	c := f.Active()
	switch strings.ToLower(key) {
	case "endpoint":
		return c.Endpoint, nil
	case "issuer":
		return c.Issuer, nil
	case "account":
		return c.Account, nil
	case "format":
		return c.Format, nil
	case "current":
		return f.Current, nil
	default:
		return "", fmt.Errorf("unknown key %q", key)
	}
}
