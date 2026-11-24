// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"fmt"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

// BindingVersion is the approval binding a key's policy asks for op: 2 when its
// step-up rule says binding 2, 1 for a step-up rule without it (every key
// created before v2), 0 when no rule on op asks for a step-up. A vault takes
// only the version its rule names, so rules on one op that disagree are
// refused rather than guessed.
func BindingVersion(p vault.KeyPolicy, op vault.Operation) (int, error) {
	version := 0
	for _, rule := range p.Operations {
		covers := false
		for _, o := range rule.Ops {
			if o == op {
				covers = true
				break
			}
		}
		if !covers {
			continue
		}
		for _, c := range rule.Requires {
			if c.OidcStepUp == nil {
				continue
			}
			v := 1
			if c.OidcStepUp.Binding == 2 {
				v = 2
			} else if c.OidcStepUp.Binding > 2 {
				return 0, fmt.Errorf("the key's policy asks for approval binding %d on %s, which this CLI does not know", c.OidcStepUp.Binding, op)
			}
			if version != 0 && version != v {
				return 0, fmt.Errorf("the key's policy asks for both binding v1 and v2 on %s", op)
			}
			version = v
		}
	}
	return version, nil
}

// KeyTarget is where a key lives, as the control plane reports it.
type KeyTarget struct {
	Handle    string
	Endpoints []string
	MRENCLAVE string
	AttServer string
	AttToken  string
	Bearer    string // a token the key's vaults accept, to read its policy
}

// KeyApproval says how to approve op on a key: Binding 2 with the members'
// identities, or 1 as before. It reads the key's policy at its vaults, which
// are the authority on it. A policy it cannot read (an older vault build, a
// caller without read access) gives binding 1, today's behaviour: the vault
// refuses an approval of the wrong version, so guessing low weakens nothing.
func KeyApproval(ctx context.Context, t KeyTarget, op vault.Operation) (binding int, ids []PinnedIdentity, policyVersion uint32, err error) {
	if len(t.Endpoints) == 0 || t.MRENCLAVE == "" {
		return 1, nil, 0, nil // no addressing (an older control plane): as before
	}
	verify, err := verifyPolicy(t.MRENCLAVE, t.AttServer, t.AttToken)
	if err != nil {
		return 0, nil, 0, err
	}
	var policy *vault.KeyPolicy
	for _, ep := range t.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(t.Bearer)})
		if derr != nil {
			continue
		}
		p, v, perr := c.GetPolicy(ctx, t.Handle)
		c.Close()
		if perr == nil {
			policy, policyVersion = &p, v
			break
		}
	}
	if policy == nil {
		return 1, nil, 0, nil
	}
	binding, err = BindingVersion(*policy, op)
	if err != nil || binding != 2 {
		return binding, nil, policyVersion, err
	}
	ids, err = ConstellationIdentities(ctx, t.Endpoints, t.MRENCLAVE, t.AttServer, t.AttToken)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("read the vaults' identities: %w", err)
	}
	return 2, ids, policyVersion, nil
}
