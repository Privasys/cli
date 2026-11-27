// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

// ThresholdKeyType is the vault key type of a threshold Ed25519 key.
const ThresholdKeyType = "FrostEd25519"

// CreateThresholdKeyInVault creates a threshold Ed25519 key (FROST) across
// every vault of the constellation by distributed key generation: no vault,
// and not this CLI, ever holds the key. threshold is how many vaults must
// sign together (0 = the constellation's own threshold). Returns the result
// and the 32-byte Ed25519 public key.
func CreateThresholdKeyInVault(ctx context.Context, p VaultCreateParams, threshold int) (*Result, []byte, error) {
	cert, cnf, err := generateClientCert(p.Sub)
	if err != nil {
		return nil, nil, fmt.Errorf("client cert: %w", err)
	}
	grant, addr, err := p.MintGrant(ctx, cnf)
	if err != nil {
		return nil, nil, err
	}
	n := len(addr.Endpoints)
	if n < 2 {
		return nil, nil, fmt.Errorf("a threshold key needs at least 2 vaults; the constellation has %d", n)
	}
	if threshold == 0 {
		threshold = addr.Threshold
	}
	if threshold < 2 {
		threshold = 2
	}
	if threshold > n {
		return nil, nil, fmt.Errorf("threshold %d is more than the constellation's %d vaults", threshold, n)
	}
	verify, err := verifyPolicy(addr.MRENCLAVE, addr.AttServer, p.AttToken)
	if err != nil {
		return nil, nil, err
	}
	opts := vault.DialOptions{ClientCert: cert, VaultPolicy: verify}
	if err := withCreateApproval(ctx, p, addr, grant, &opts); err != nil {
		return nil, nil, err
	}
	con := vault.NewStaticConstellation(addr.Endpoints, opts)
	key, err := con.CreateThresholdKey(ctx, addr.Handle, grant, threshold)
	if err != nil {
		return nil, nil, err
	}
	return &Result{
		Handle: key.Handle, Created: n, Total: n, Threshold: threshold,
		Exportable: false, Thumbprint: cnf,
	}, key.PublicKey, nil
}

// SignThresholdInVault signs message with a threshold Ed25519 key: every
// reachable vault of its constellation is asked, each checks the key's
// policy against the owner's bearer, and the signature is aggregated and
// verified by one of them.
func SignThresholdInVault(ctx context.Context, p VaultOpParams, message []byte) (*SignResult, error) {
	verify, err := verifyPolicy(p.MRENCLAVE, p.AttServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	con := vault.NewStaticConstellation(p.Endpoints, vault.DialOptions{AuthToken: staticToken(p.OwnerToken), VaultPolicy: verify})
	sig, alg, err := con.SignThreshold(ctx, p.Handle, message, 0)
	if err != nil {
		return nil, fmt.Errorf("threshold sign %q: %w", p.Handle, err)
	}
	return &SignResult{Signature: sig, Alg: alg, Vault: fmt.Sprintf("%d vaults", len(p.Endpoints))}, nil
}

// RenewConstellation addresses one side of a threshold key's renewal.
type RenewConstellation struct {
	ID                string
	Endpoints         []string
	MRENCLAVE         string
	AttestationServer string
	Threshold         int
	Audience          string // the audience its vaults accept ("" = the default)
}

// ThresholdRenewParams describes renewing a threshold key.
type ThresholdRenewParams struct {
	Issuer string
	Sub    string
	// Token gives the owner's bearer for vaults of an audience: the old and
	// the new vaults may accept different ones.
	Token     TokenFor
	AttToken  string // aud=attestation-server, to verify the vaults' quotes
	Threshold int    // 0 = the target constellation's threshold
	// Mint asks the platform for a grant (bound to cnf) for the key's handle
	// on the active constellation: returns the grant, the handle, the target
	// and the key's current home.
	Mint func(ctx context.Context, cnf string) (grant, handle string, target, home RenewConstellation, err error)
	// DisplayName names the key on the owner's approval, e.g. "key card1 in
	// vault wallet-card-test": owner-given names only, as it travels in the
	// wallet push.
	DisplayName string
	Out         io.Writer
	Open        BrowserOpener
	// ApproveV2 asks the owner for a binding v2 approval (a.Audience is the
	// home vaults' audience): used when the home vaults read every step-up
	// as binding v2.
	ApproveV2 func(ctx context.Context, a ApprovalV2) (string, error)
}

// ThresholdRenewResult is a renewed threshold key.
type ThresholdRenewResult struct {
	Handle        string `json:"handle"`
	PublicKey     []byte `json:"-"`
	Vaults        int    `json:"vaults"`
	Threshold     int    `json:"threshold"`
	InPlace       bool   `json:"in_place"`
	Constellation string `json:"constellation_id"`
}

// RenewThresholdKeyInVault renews a threshold key under its handle and public
// key on the active constellation (in place, or moving it there), as `secrets
// renew` does for a secret: the owner approves the move in the wallet, the old
// vaults deal their shares to the new ones, no key material passes through
// this CLI.
func RenewThresholdKeyInVault(ctx context.Context, p ThresholdRenewParams) (*ThresholdRenewResult, error) {
	cert, cnf, err := generateClientCert(p.Sub)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	grant, handle, target, home, err := p.Mint(ctx, cnf)
	if err != nil {
		return nil, err
	}
	targetVerify, err := verifyPolicy(target.MRENCLAVE, target.AttestationServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	homeVerify, err := verifyPolicy(home.MRENCLAVE, home.AttestationServer, p.AttToken)
	if err != nil {
		return nil, err
	}
	homeTok, err := p.Token(ctx, home.Audience)
	if err != nil {
		return nil, err
	}
	targetTok, err := p.Token(ctx, target.Audience)
	if err != nil {
		return nil, err
	}
	// Vaults without binding v1 approve the move with a binding v2 reshare
	// naming their members; older vaults take the v1 approval.
	homeDial := vault.DialOptions{VaultPolicy: homeVerify}
	var homeIDs []PinnedIdentity
	if VaultsReadAllV2(ctx, KeyTarget{Handle: handle, Endpoints: home.Endpoints, MRENCLAVE: home.MRENCLAVE,
		AttServer: home.AttestationServer, AttToken: p.AttToken, Bearer: homeTok}) {
		if p.ApproveV2 == nil {
			return nil, fmt.Errorf("renewing %q needs the owner's approval in the Privasys Wallet", handle)
		}
		if homeIDs, err = ConstellationIdentities(ctx, home.Endpoints, home.MRENCLAVE, home.AttestationServer, p.AttToken); err != nil {
			return nil, fmt.Errorf("read the vaults' identities: %w", err)
		}
		homeDial.BindingMembers = memberIDs(homeIDs)
	}
	n := len(target.Endpoints)
	t := p.Threshold
	if t == 0 {
		t = target.Threshold
	}
	if t < 2 {
		t = 2
	}
	if t > n {
		return nil, fmt.Errorf("threshold %d is more than the target constellation's %d vaults", t, n)
	}
	inPlace := home.ID == target.ID
	key, err := vault.ReshareThresholdKey(ctx, vault.ReshareParams{
		Handle: handle, Grant: grant, Threshold: t,
		Home: home.Endpoints, HomeDial: homeDial, HomeToken: homeTok,
		Target: target.Endpoints,
		TargetDial: vault.DialOptions{
			ClientCert: cert, VaultPolicy: targetVerify, AuthToken: vault.StaticToken(targetTok),
		},
		TargetMrenclave: target.MRENCLAVE,
		InPlace:         inPlace,
		StepUp: func(ctx context.Context, a vault.ReshareApproval) (string, error) {
			// The wallet shows the exact build the key's shares go to: the
			// vaults deal only to vaults of that build, so this is what the
			// owner approves.
			build := "the same vault build as today"
			if !strings.EqualFold(home.MRENCLAVE, target.MRENCLAVE) {
				build = "a NEW vault build"
			}
			helpers := make([]string, len(a.Helpers))
			for i, h := range a.Helpers {
				helpers[i] = strconv.Itoa(int(h))
			}
			// Every input of the resharing context, so the wallet recomputes
			// the digest it signs from what it shows.
			actx := approvalContext{
				"key_type":         ThresholdKeyType,
				"target_mrenclave": a.TargetMrenclave,
				"target_vaults":    strings.Join(a.Vaults, ","),
				"threshold":        strconv.Itoa(int(a.Threshold)),
				"helpers":          strings.Join(helpers, ","),
				"public_key":       base64.RawURLEncoding.EncodeToString(a.GroupKey),
				"summary": fmt.Sprintf("Renew this threshold Ed25519 key onto %d vaults (any %d sign) of %s, "+
					"MRENCLAVE %s. Its public key does not change.", n, t, build, strings.ToLower(target.MRENCLAVE)),
			}
			actx.name(p.DisplayName)
			if len(homeIDs) > 0 {
				return p.ApproveV2(ctx, ApprovalV2{Operation: vault.BindReshare, Handle: handle, Target: a.ContextHex,
					PolicyVersion: uint64(a.PolicyVersion), Identities: homeIDs, Audience: home.Audience, Context: actx})
			}
			out := p.Out
			if out == nil {
				out = os.Stderr
			}
			// The old vaults check the approval: it is issued for their
			// audience.
			return RequestStepUpViaBrowserFor(ctx, p.Issuer, homeTok, home.Audience, "reshare", handle, a.ContextHex,
				a.PolicyVersion, actx, p.Open, out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &ThresholdRenewResult{
		Handle: key.Handle, PublicKey: key.PublicKey, Vaults: n, Threshold: t,
		InPlace: inPlace, Constellation: target.ID,
	}, nil
}
