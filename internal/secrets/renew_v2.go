// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"fmt"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

// RenewV2Params renews one generation of a user secret on binding v2 vaults.
type RenewV2Params struct {
	Issuer string // privasys.id, which signs the grant
	Bearer string // the owner's session, for the grant
	Sub    string
	Base   string // users/<sub>/<name>
	Old    string // the generation being renewed
	OldGen int
	// Material is the secret's value, exported by the owner. Never logged.
	Material  []byte
	Threshold int
	AttToken  string
	// Source holds Old; Target receives the successor (the active
	// constellation). The tokens are the owner's bearers for each one's audience.
	Source, Target           *api.VaultDirectory
	SourceToken, TargetToken string
}

// RenewV2 creates the next generation of a secret with the same value. On the
// same constellation the vaults copy the predecessor's policy; to another one,
// the policy is read from every source vault and carried, under the source's
// billing configuration. The old generation is left as it is: deleting it
// takes the owner's approval, which the caller asks for.
func RenewV2(ctx context.Context, p RenewV2Params) (*Result, error) {
	if len(p.Material) == 0 {
		return nil, errors.New("empty secret material")
	}
	if p.Threshold < 2 {
		p.Threshold = 2
	}
	if len(p.Target.Endpoints) < p.Threshold {
		return nil, fmt.Errorf("the target constellation has %d vaults, fewer than the threshold %d", len(p.Target.Endpoints), p.Threshold)
	}
	next := GenerationHandle(p.Base, p.OldGen+1)

	// The successor is what the old generation is: a vault takes a carried
	// key's exportability and type from the grant, so the grant must not
	// differ from the key it renews.
	oldInfo, err := keyInfoAt(ctx, p.Source, p.SourceToken, p.AttToken, p.Old)
	if err != nil {
		return nil, err
	}
	if oldInfo.KeyType != vault.RawShare || !oldInfo.Exportable {
		return nil, fmt.Errorf("%s is a %s key (exportable: %t), not a secret this command renews", p.Old, oldInfo.KeyType, oldInfo.Exportable)
	}

	renewal := vault.Renewal{Predecessor: p.Old}
	if p.Source.ID != p.Target.ID {
		policy, version, err := carriedPolicy(ctx, p.Source, p.SourceToken, p.AttToken, p.Old)
		if err != nil {
			return nil, err
		}
		ids, err := ConstellationIdentities(ctx, p.Source.Endpoints, p.Source.MRENCLAVE, p.Source.AttestationServer, p.AttToken)
		if err != nil {
			return nil, fmt.Errorf("the source vaults' identity: %w", err)
		}
		check, err := vault.NewKeyCheck(p.Material)
		if err != nil {
			return nil, err
		}
		exportable := oldInfo.Exportable
		renewal = vault.Renewal{Policy: policy, PolicyVersion: version, SourceBillingID: ids[0].BillingID(), KeyCheck: &check,
			CarriedExportable: &exportable, CarriedKeyType: oldInfo.KeyType}
	}

	cert, cnf, err := generateClientCert(p.Sub)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	grant, err := requestGrant(ctx, CreateParams{Issuer: p.Issuer, Bearer: p.Bearer, Sub: p.Sub, Handle: next,
		Exportable: oldInfo.Exportable, bindingV2: true}, cnf)
	if err != nil {
		return nil, err
	}
	verify, err := verifyPolicy(p.Target.MRENCLAVE, p.Target.AttestationServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	shares, err := vault.ShamirSplit(p.Material, p.Threshold, len(p.Target.Endpoints))
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}
	created := 0
	var firstErr error
	for i, ep := range p.Target.Endpoints {
		share := vault.ShareToBytes(shares[i])
		for j := range shares[i].Data {
			shares[i].Data[j] = 0
		}
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{ClientCert: cert, AuthToken: staticToken(p.TargetToken), VaultPolicy: verify})
		if derr == nil {
			_, derr = c.CreateKeyRenewal(ctx, next, share, grant, renewal)
			c.Close()
		}
		for j := range share {
			share[j] = 0
		}
		if derr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ep, derr)
			}
			continue
		}
		created++
	}
	res := &Result{Handle: next, Created: created, Total: len(p.Target.Endpoints), Threshold: p.Threshold, Exportable: true, Thumbprint: cnf}
	if created < p.Threshold {
		return res, fmt.Errorf("only %d of %d vaults accepted the renewal (need %d), so %s is unchanged: %v",
			created, len(p.Target.Endpoints), p.Threshold, p.Old, firstErr)
	}
	return res, nil
}

// carriedPolicy reads the policy of handle from every source vault holding it.
// They must agree: the successor is created under that one policy.
func carriedPolicy(ctx context.Context, src *api.VaultDirectory, ownerTok, attTok, handle string) ([]byte, uint32, error) {
	verify, err := verifyPolicy(src.MRENCLAVE, src.AttestationServer, attTok)
	if err != nil {
		return nil, 0, err
	}
	var policy []byte
	var version uint32
	var digest string
	for _, ep := range src.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
		if derr != nil {
			return nil, 0, fmt.Errorf("read the policy to carry from %s: %w", ep, derr)
		}
		raw, v, perr := c.GetPolicyRaw(ctx, handle)
		c.Close()
		if perr != nil {
			return nil, 0, fmt.Errorf("read the policy to carry from %s: %w", ep, perr)
		}
		pd, perr := vault.PolicyDigestJSON(raw)
		if perr != nil {
			return nil, 0, fmt.Errorf("the policy %s holds: %w", ep, perr)
		}
		if policy == nil {
			policy, version, digest = raw, v, pd
		} else if pd != digest || v != version {
			return nil, 0, fmt.Errorf("the source vaults hold different policies for %s: resolve that first", handle)
		}
	}
	return policy, version, nil
}

// keyInfoAt reads a key's public metadata from every vault of d that holds it,
// and refuses when they disagree on its type or exportability: a renewal
// carries those, so they must be the key's on every member.
func keyInfoAt(ctx context.Context, d *api.VaultDirectory, ownerTok, attTok, handle string) (*vault.KeyInfo, error) {
	verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
	if err != nil {
		return nil, err
	}
	var first *vault.KeyInfo
	var lastErr error
	for _, ep := range d.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
		if derr != nil {
			lastErr = derr
			continue
		}
		info, ierr := c.GetKeyInfo(ctx, handle)
		c.Close()
		if ierr != nil {
			lastErr = ierr
			continue
		}
		if first == nil {
			first = &info
		} else if info.KeyType != first.KeyType || info.Exportable != first.Exportable {
			return nil, fmt.Errorf("the vaults disagree on %s's type or exportability: resolve that first", handle)
		}
	}
	if first == nil {
		return nil, fmt.Errorf("read %s: %v", handle, lastErr)
	}
	return first, nil
}
