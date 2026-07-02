// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseJSONDataArg(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{`{"k":"v"}`, `{"k":"v"}`, false},
		// The cmd.exe single-quote trap: literal quotes around valid JSON.
		{`'{"query":"bertrand foing","count":0}'`, `{"query":"bertrand foing","count":0}`, false},
		{`  '{"k":1}'  `, `{"k":1}`, false},
		// A quoted non-JSON stays an error.
		{`'nope'`, "", true},
		{`{broken`, "", true},
	}
	for _, c := range cases {
		got, err := parseJSONDataArg(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseJSONDataArg(%q): expected an error", c.in)
			} else if strings.Contains(c.in, "'") && !strings.Contains(err.Error(), "hint") {
				t.Errorf("parseJSONDataArg(%q): error should carry a quoting hint: %v", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseJSONDataArg(%q): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("parseJSONDataArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.22.0", "0.24.0", true},
		{"0.24.0", "0.24.0", false},
		{"0.24.1", "0.24.0", false},
		{"0.9.0", "0.10.0", true},
		{"dev", "0.1.0", true}, // dev builds always update
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestDetectInstallChannel(t *testing.T) {
	cases := map[string]string{
		`C:\Users\me\scoop\shims\privasys.exe`:            "scoop",
		"/opt/homebrew/bin/privasys":                      "brew",
		"/home/linuxbrew/.linuxbrew/bin/privasys":         "brew",
		"/usr/local/Cellar/privasys/0.24.0/bin/privasys":  "brew",
		"/home/me/.local/bin/privasys":                    "direct",
		`C:\Users\me\AppData\Local\privasys\privasys.exe`: "direct",
	}
	for in, want := range cases {
		if got := detectInstallChannel(in); got != want {
			t.Errorf("detectInstallChannel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("hello world")
	sum := sha256.Sum256(data)
	sums := []byte("deadbeef  other.tar.gz\n" + hex.EncodeToString(sum[:]) + "  asset.tar.gz\n")
	if err := verifyChecksum(sums, "asset.tar.gz", data); err != nil {
		t.Errorf("verifyChecksum: %v", err)
	}
	if err := verifyChecksum(sums, "asset.tar.gz", []byte("tampered")); err == nil {
		t.Error("verifyChecksum: tampered data must fail")
	}
	if err := verifyChecksum(sums, "missing.tar.gz", data); err == nil {
		t.Error("verifyChecksum: missing entry must fail")
	}
}
