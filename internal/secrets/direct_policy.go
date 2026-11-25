// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

// A direct policy change updates a key's policy on its vaults themselves,
// with the owner's approval as the bearer: the approval never passes through
// the control plane. It serves keys the control plane has no route for
// (machine data keys, registry credentials).

// MemberPolicy is a key's policy as one member holds it.
type MemberPolicy struct {
	Endpoint string
	Raw      json.RawMessage
	Version  uint32
	PD       string
}

// ReadMemberPolicies reads the key's policy from every member of d over
// pinned RA-TLS. Every member must answer: a change is never planned on a
// partial view.
func ReadMemberPolicies(ctx context.Context, d *api.VaultDirectory, ownerTok, attTok, handle string) ([]MemberPolicy, error) {
	verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
	if err != nil {
		return nil, err
	}
	out := make([]MemberPolicy, 0, len(d.Endpoints))
	for _, ep := range d.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
		if derr != nil {
			return nil, fmt.Errorf("read the policy on %s: %w", ep, derr)
		}
		raw, v, perr := c.GetPolicyRaw(ctx, handle)
		c.Close()
		if perr != nil {
			return nil, fmt.Errorf("read the policy on %s: %w", ep, perr)
		}
		pd, perr := vault.PolicyDigestJSON(raw)
		if perr != nil {
			return nil, fmt.Errorf("the policy on %s: %w", ep, perr)
		}
		out = append(out, MemberPolicy{Endpoint: ep, Raw: raw, Version: v, PD: pd})
	}
	return out, nil
}

// DirectPlan is what a direct change does: from Current (at Version) to
// Target, in the vaults' stored form, on the members in ToUpdate. Done are
// members that already hold Target (a re-run after a partial failure).
type DirectPlan struct {
	Current  json.RawMessage
	Version  uint32
	Target   json.RawMessage
	TargetPD string
	ToUpdate []string
	Done     []string
}

// PlanDirectChange works out the change from what the members hold. When
// they all agree, every member moves from their policy to expect(it). When
// they are split in two, it converges a partial earlier run: one group must
// hold the policy whose expected change the other group already holds, and
// only the first group is updated. Anything else is refused, naming which
// members hold which version.
func PlanDirectChange(ctx context.Context, members []MemberPolicy, expect func(json.RawMessage) (json.RawMessage, error), canon Canonicaliser) (DirectPlan, error) {
	groups := map[string][]MemberPolicy{}
	var order []string
	for _, m := range members {
		if _, ok := groups[m.PD]; !ok {
			order = append(order, m.PD)
		}
		groups[m.PD] = append(groups[m.PD], m)
	}
	target := func(from []MemberPolicy) (json.RawMessage, string, error) {
		next, err := expect(from[0].Raw)
		if err != nil {
			return nil, "", err
		}
		stored, err := canon(ctx, next)
		if err != nil {
			return nil, "", err
		}
		pd, err := vault.PolicyDigestJSON(stored)
		return stored, pd, err
	}
	plan := func(cur MemberPolicy, from, done []MemberPolicy, t json.RawMessage, tpd string) DirectPlan {
		p := DirectPlan{Current: cur.Raw, Version: cur.Version, Target: t, TargetPD: tpd}
		for _, m := range from {
			p.ToUpdate = append(p.ToUpdate, m.Endpoint)
		}
		for _, m := range done {
			p.Done = append(p.Done, m.Endpoint)
		}
		return p
	}
	switch len(order) {
	case 1:
		g := groups[order[0]]
		for _, m := range g[1:] {
			if m.Version != g[0].Version {
				return DirectPlan{}, errors.New("the vaults hold the same policy at different versions; resolve that first")
			}
		}
		t, tpd, err := target(g)
		if err != nil {
			return DirectPlan{}, err
		}
		if tpd == order[0] {
			return plan(g[0], nil, g, t, tpd), nil // already done everywhere
		}
		return plan(g[0], g, nil, t, tpd), nil
	case 2:
		a, b := groups[order[0]], groups[order[1]]
		for _, pair := range [][2][]MemberPolicy{{a, b}, {b, a}} {
			from, done := pair[0], pair[1]
			t, tpd, err := target(from)
			if err == nil && tpd == done[0].PD {
				return plan(from[0], from, done, t, tpd), nil
			}
		}
	}
	return DirectPlan{}, fmt.Errorf("the vaults hold different policies, and not as one interrupted change: %s; resolve that first", describeMembers(members))
}

func describeMembers(members []MemberPolicy) string {
	parts := make([]string, 0, len(members))
	for _, m := range members {
		parts = append(parts, fmt.Sprintf("%s v%d (%s…)", m.Endpoint, m.Version, m.PD[:12]))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// DirectApproval is how the vaults take the change: the bearer (the owner's
// approval, or their token when the rule asks for none), the members a v2
// approval binds, and, for update_policy_from, the digest of the policy
// replaced.
type DirectApproval struct {
	Bearer         string
	BindingMembers []string
	ReplacedPD     string
}

// ApplyDirect sends the plan's target to each member of ToUpdate, and
// returns each member's error (nil when it took the change).
func ApplyDirect(ctx context.Context, d *api.VaultDirectory, attTok, handle string, p DirectPlan, a DirectApproval) map[string]error {
	out := map[string]error{}
	verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
	for _, ep := range p.ToUpdate {
		if err != nil {
			out[ep] = err
			continue
		}
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify,
			AuthToken: staticToken(a.Bearer), BindingMembers: a.BindingMembers})
		if derr != nil {
			out[ep] = derr
			continue
		}
		if a.ReplacedPD != "" {
			_, out[ep] = c.UpdatePolicyRawFrom(ctx, handle, p.Target, a.ReplacedPD)
		} else {
			_, out[ep] = c.UpdatePolicyRaw(ctx, handle, p.Target)
		}
		c.Close()
	}
	return out
}
