// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// Same independently computed vector as the runtime's
// TestRepositoryPasswordVector: the CLI and the enclave must derive the same
// password from the same key, or an owner's last-resort restore fails.
func TestBackupRepositoryPasswordMatchesRuntime(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := backupRepositoryPassword(key)
	if err != nil {
		t.Fatal(err)
	}
	if want := "6cfb67512396b8fdade1b023d37f24e64838d7ec6468b255030e35331684bc29"; got != want {
		t.Fatalf("password = %s, want %s", got, want)
	}
}

func TestAppKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "app.key")
	k, err := appKeyMaterial(out, "")
	if err != nil || len(k) != 32 {
		t.Fatalf("generate: %v (%d bytes)", err, len(k))
	}
	onDisk, _ := os.ReadFile(out)
	if string(onDisk) != string(k) {
		t.Fatal("the owner's copy differs from the key")
	}
	if _, err := appKeyMaterial(out, ""); err == nil {
		t.Fatal("an existing key file was overwritten")
	}
	back, err := appKeyMaterial("", out)
	if err != nil || string(back) != string(k) {
		t.Fatalf("read back: %v", err)
	}
	short := filepath.Join(dir, "short.key")
	_ = os.WriteFile(short, []byte("too short"), 0o600)
	if _, err := appKeyMaterial("", short); err == nil {
		t.Fatal("a key of the wrong size was accepted")
	}
}
