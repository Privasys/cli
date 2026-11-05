// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oci

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Against a real registry (GHCR) and a public image: exercises the token
// challenge, the index walk and the base64 label. Opt in with PRIVASYS_OCI_LIVE=1.
func TestFetchLabelLiveGHCR(t *testing.T) {
	if os.Getenv("PRIVASYS_OCI_LIVE") == "" {
		t.Skip("set PRIVASYS_OCI_LIVE=1 to run against ghcr.io")
	}
	raw, err := NewClient().FetchLabel(context.Background(), "ghcr.io/privasys/container-app-register:v0.1.0", "org.privasys.manifest", nil)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || len(m.Tools) == 0 {
		t.Fatalf("manifest not decoded: %v (%d bytes)", err, len(raw))
	}
}
