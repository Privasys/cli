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
func CheckRetireChange(ctx context.Context, current, proposed json.RawMessage, digest string, canon Canonicaliser) error {
	if canon == nil {
		return errors.New("no vault to canonicalise the policies with")
	}
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
	root, _ := doc.(map[string]any)
	// Tees are referred to by index ({"Tee": n}), which the control plane
	// renumbers only in operations[].principals. One anywhere else would
	// change meaning when a tee is removed, so it is refused.
	if teeRefOutsideRules(root) {
		return refuse("the key's policy refers to a TEE by position outside its operation rules")
	}
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
	if ops, ok := root["operations"].([]any); ok {
		root["operations"] = renumberTeeRefs(ops, idx)
	}
	expected, err := json.Marshal(root)
	if err != nil {
		return err
	}
	// The stored policy writes every default out; the control plane's typed
	// policy leaves them out. Both go through the vault's own
	// canonicalisation, which writes the defaults on both sides alike, and
	// the digests of what it returns are compared.
	wantPD, err := canonicalPD(ctx, canon, expected)
	if err != nil {
		return fmt.Errorf("the expected policy: %w", err)
	}
	gotPD, err := canonicalPD(ctx, canon, proposed)
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

// teeIndex is n when p is a {"Tee": n} reference.
func teeIndex(p any) (int64, bool) {
	m, ok := p.(map[string]any)
	if !ok || len(m) != 1 {
		return 0, false
	}
	n, ok := m["Tee"].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// renumberTeeRefs is what the control plane's retirePolicy does to the rules
// when the tee at removed goes: a {"Tee": i} above it becomes i-1, one naming
// it is dropped, and a rule left naming nobody is dropped.
func renumberTeeRefs(rules []any, removed int) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		// A null or missing principals list is an empty one, as in the
		// control plane's typed rule, and the rule is dropped like any rule
		// left naming nobody.
		ps, ok := rule["principals"].([]any)
		if !ok && rule["principals"] != nil {
			out = append(out, r)
			continue
		}
		kept := make([]any, 0, len(ps))
		for _, p := range ps {
			if i, isTee := teeIndex(p); isTee {
				if i == int64(removed) {
					continue
				}
				if i > int64(removed) {
					p = map[string]any{"Tee": json.Number(fmt.Sprint(i - 1))}
				}
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			continue
		}
		rule["principals"] = kept
		out = append(out, rule)
	}
	return out
}

// teeRefOutsideRules reports a {"Tee": n} reference anywhere but in an
// operation rule's principals.
func teeRefOutsideRules(root map[string]any) bool {
	for k, v := range root {
		if k != "operations" {
			if hasTeeIndexRef(v) {
				return true
			}
			continue
		}
		rules, ok := v.([]any)
		if !ok {
			if hasTeeIndexRef(v) {
				return true
			}
			continue
		}
		for _, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				if hasTeeIndexRef(r) {
					return true
				}
				continue
			}
			for rk, rv := range rule {
				if rk != "principals" && hasTeeIndexRef(rv) {
					return true
				}
			}
		}
	}
	return false
}

// Canonicaliser returns a policy as the key's vaults would store it, every
// field written (Client.CanonicalPolicy), or their refusal.
type Canonicaliser func(ctx context.Context, policy json.RawMessage) (json.RawMessage, error)

func canonicalPD(ctx context.Context, canon Canonicaliser, policy json.RawMessage) (string, error) {
	stored, err := canon(ctx, policy)
	if err != nil {
		return "", err
	}
	return vault.PolicyDigestJSON(stored)
}

// VaultCanonicaliser asks every vault of d, over pinned RA-TLS, for the
// policy as it would store it; they must all give the same.
func VaultCanonicaliser(d *api.VaultDirectory, ownerTok, attTok string) Canonicaliser {
	return func(ctx context.Context, policy json.RawMessage) (json.RawMessage, error) {
		verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
		if err != nil {
			return nil, err
		}
		var first json.RawMessage
		var firstPD string
		for _, ep := range d.Endpoints {
			c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
			if derr != nil {
				return nil, fmt.Errorf("canonicalise on %s: %w", ep, derr)
			}
			stored, _, cerr := c.CanonicalPolicy(ctx, policy)
			c.Close()
			if cerr != nil {
				return nil, fmt.Errorf("the vault %s refuses the policy: %w", ep, cerr)
			}
			pd, perr := vault.PolicyDigestJSON(stored)
			if perr != nil {
				return nil, fmt.Errorf("the vault %s: %w", ep, perr)
			}
			if first == nil {
				first, firstPD = stored, pd
			} else if pd != firstPD {
				return nil, fmt.Errorf("the key's vaults canonicalise the policy differently")
			}
		}
		if first == nil {
			return nil, errors.New("no vault to canonicalise the policy with")
		}
		return first, nil
	}
}
