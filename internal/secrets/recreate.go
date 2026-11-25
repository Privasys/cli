// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Privasys/enclave-vaults-client/go/vault"

	"github.com/Privasys/cli/internal/api"
)

// reCreateApproval is what creating a re-created name (".../new-<k>",
// formats §9.3.1) needs: the owner's create approval, used as the bearer of
// the create, and the members it binds. For any other handle it returns
// nothing, and a handle beneath a new-<k> segment (only a linked renewal may
// be created there) is refused.
//
// The approval binds the grant's policy in the vaults' stored form, read
// from every member over pinned RA-TLS; the policy must be owned by the
// subject the vaults will see (p.ApprovalSub).
func reCreateApproval(ctx context.Context, p VaultCreateParams, addr VaultAddressing, grant string) (bearer string, members []string, err error) {
	if !vault.IsReCreatedName(addr.Handle) {
		if vault.IsBeneathReCreatedName(addr.Handle) {
			return "", nil, fmt.Errorf("%s lies beneath a re-created name, where only a renewal is created", addr.Handle)
		}
		return "", nil, nil
	}
	if p.ApproveCreate == nil {
		return "", nil, errors.New("re-creating a deleted name needs the owner's approval in the Privasys Wallet")
	}
	if p.ApprovalSub == nil {
		return "", nil, errors.New("no subject to check the key's owner against")
	}
	sub, err := p.ApprovalSub(ctx, addr.Audience)
	if err != nil {
		return "", nil, err
	}
	policy, err := GrantPolicy(grant, sub)
	if err != nil {
		return "", nil, err
	}
	ids, err := ConstellationIdentities(ctx, addr.Endpoints, addr.MRENCLAVE, addr.AttServer, p.AttToken)
	if err != nil {
		return "", nil, fmt.Errorf("read the vaults' identities: %w", err)
	}
	for _, id := range ids {
		if !id.Has(vault.CapabilityTombstones) {
			return "", nil, fmt.Errorf("the vault %s does not keep deleted names, so it cannot re-create one", id.MemberID())
		}
	}
	dir := &api.VaultDirectory{Endpoints: addr.Endpoints, MRENCLAVE: addr.MRENCLAVE, AttestationServer: addr.AttServer}
	stored, err := VaultCanonicaliser(dir, "", p.AttToken)(ctx, policy)
	if err != nil {
		return "", nil, fmt.Errorf("the key's policy: %w", err)
	}
	a, err := CreateApproval(addr.Handle, stored, ids, addr.Audience,
		map[string]string{"summary": "Create a new key under a deleted name: " + addr.Handle})
	if err != nil {
		return "", nil, err
	}
	tok, err := p.ApproveCreate(ctx, a)
	if err != nil {
		return "", nil, err
	}
	return tok, memberIDs(ids), nil
}

// withCreateApproval adds a re-created name's approval to the create's dial
// options: the approval as the bearer, and the members it binds.
func withCreateApproval(ctx context.Context, p VaultCreateParams, addr VaultAddressing, grant string, opts *vault.DialOptions) error {
	bearer, members, err := reCreateApproval(ctx, p, addr, grant)
	if err != nil || bearer == "" {
		return err
	}
	opts.AuthToken = staticToken(bearer)
	opts.BindingMembers = members
	return nil
}

// CheckReCreatedName applies formats §9.3.1's checks before a vault key
// resolved to a re-created name ("vaults/<vault>/<name>/new-<k>") is used,
// on every member over pinned RA-TLS: the key was created with the owner's
// approval, no higher new-<j> of the name is live, and neither the base name
// nor a lower new-<j> is live (each is deleted or absent). Any failure
// refuses the key, with no fallback to another one. A handle without a
// new-<k> segment passes. A renewal beneath a re-created name is refused
// for now: its chain is not checked yet.
func CheckReCreatedName(ctx context.Context, d *api.VaultDirectory, ownerTok, attTok, vaultID, name, handle string) error {
	base := "vaults/" + vaultID + "/" + name
	rest, ok := strings.CutPrefix(handle, base+"/")
	if !ok || !strings.HasPrefix(rest, "new-") {
		return nil
	}
	seg, beneath, _ := strings.Cut(rest, "/")
	k, err := strconv.Atoi(strings.TrimPrefix(seg, "new-"))
	if err != nil || k < 2 {
		return fmt.Errorf("%s is not a re-created name", handle)
	}
	if beneath != "" {
		return fmt.Errorf("%s is a renewal of a re-created name, which this CLI does not check yet", handle)
	}
	verify, err := verifyPolicy(d.MRENCLAVE, d.AttestationServer, attTok)
	if err != nil {
		return err
	}
	read := 0
	for _, ep := range d.Endpoints {
		c, derr := vault.Dial(ctx, vaultReg(ep), vault.DialOptions{VaultPolicy: verify, AuthToken: staticToken(ownerTok)})
		if derr != nil {
			return fmt.Errorf("check %s on %s: %w", handle, ep, derr)
		}
		info, ierr := c.GetKeyInfo(ctx, handle)
		keys, lerr := c.ListKeys(ctx)
		c.Close()
		if ierr != nil {
			return fmt.Errorf("check %s on %s: %w", handle, ep, ierr)
		}
		if lerr != nil {
			return fmt.Errorf("list keys on %s: %w", ep, lerr)
		}
		if !info.CreatedByOwnerApproval {
			return fmt.Errorf("the vault %s does not record %s as created with the owner's approval; refusing it", ep, handle)
		}
		for _, key := range keys {
			if key.Handle == base {
				return fmt.Errorf("the deleted name %s is live again on %s; refusing %s", base, ep, handle)
			}
			other, ok := strings.CutPrefix(key.Handle, base+"/new-")
			if !ok {
				continue
			}
			jstr, _, _ := strings.Cut(other, "/")
			j, jerr := strconv.Atoi(jstr)
			if jerr != nil || j == k {
				continue
			}
			if j > k {
				return fmt.Errorf("a later re-creation (%s) is live on %s; refusing %s", key.Handle, ep, handle)
			}
			return fmt.Errorf("an earlier re-creation (%s) is still live on %s; refusing %s", key.Handle, ep, handle)
		}
		read++
	}
	if read == 0 {
		return fmt.Errorf("no vault to check %s on", handle)
	}
	return nil
}
