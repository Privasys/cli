// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

// OIDWorkloadImageDigest is the X.509 OID a TEE profile pins an app's code
// version with (the control plane's oidWorkloadImageDigest).
const OIDWorkloadImageDigest = "1.3.6.1.4.1.65230.4.2"

// CurrentPolicy reads a key's policy, exactly as each vault of d serialised
// it, from every member over pinned RA-TLS. The members must agree on the
// policy and its version.
func CurrentPolicy(ctx context.Context, d *api.VaultDirectory, ownerTok, attTok, handle string) (json.RawMessage, uint32, error) {
	raw, v, err := carriedPolicy(ctx, d, ownerTok, attTok, handle)
	return raw, v, err
}

// CheckRetireChange checks that proposed is current with exactly the TEE
// profile pinning digest removed, as the control plane's retirePolicy builds
// it, and nothing else changed. Both are compared as canonical JSON trees, so
// fields the CLI does not know count too.
func CheckRetireChange(current, proposed json.RawMessage, digest string) error {
	refuse := func(why string) error {
		return fmt.Errorf("the requested change does more than retire %s: %s", digest, why)
	}
	want := strings.ToLower(strings.TrimSpace(digest))
	if want == "" {
		return errors.New("no measurement digest to retire")
	}
	doc, err := decodeTree(current)
	if err != nil {
		return fmt.Errorf("the key's current policy: %w", err)
	}
	// Tees are referred to by index ({"Tee": n}). Removing one would shift
	// what such a reference names, so a policy holding one is refused.
	if hasTeeIndexRef(doc) {
		return refuse("the key's policy refers to a TEE by position, which removing one would change")
	}
	root, _ := doc.(map[string]any)
	principals, _ := root["principals"].(map[string]any)
	tees, _ := principals["tees"].([]any)
	idx := -1
	for i, t := range tees {
		if teeDigest(t) == want {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("the key's policy has no measurement %s", digest)
	}
	if len(tees) <= 1 {
		return errors.New("the last measurement cannot be retired")
	}
	kept := make([]any, 0, len(tees)-1)
	kept = append(kept, tees[:idx]...)
	kept = append(kept, tees[idx+1:]...)
	principals["tees"] = kept
	expected, err := json.Marshal(root)
	if err != nil {
		return err
	}
	wantPD, err := vault.PolicyDigestJSON(expected)
	if err != nil {
		return err
	}
	gotPD, err := vault.PolicyDigestJSON(proposed)
	if err != nil {
		return fmt.Errorf("the new policy: %w", err)
	}
	if wantPD != gotPD {
		return refuse("the new policy differs from the current one in more than that measurement")
	}
	return nil
}

// decodeTree reads JSON keeping numbers exact.
func decodeTree(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// teeDigest is the workload digest a {"Tee": profile} principal pins, or "".
func teeDigest(p any) string {
	m, _ := p.(map[string]any)
	prof, _ := m["Tee"].(map[string]any)
	oids, _ := prof["required_oids"].([]any)
	for _, o := range oids {
		om, _ := o.(map[string]any)
		if id, _ := om["oid"].(string); id == OIDWorkloadImageDigest {
			v, _ := om["value"].(string)
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

// hasTeeIndexRef reports a {"Tee": <number>} reference anywhere in the tree.
func hasTeeIndexRef(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if n, ok := t["Tee"]; ok && len(t) == 1 {
			if _, isNum := n.(json.Number); isNum {
				return true
			}
		}
		for _, c := range t {
			if hasTeeIndexRef(c) {
				return true
			}
		}
	case []any:
		for _, c := range t {
			if hasTeeIndexRef(c) {
				return true
			}
		}
	}
	return false
}
