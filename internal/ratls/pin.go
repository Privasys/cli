// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	rc "enclave-os-mini/clients/go/ratls"
)

// AppPin is what an app's serving leaf must prove before the caller's token is
// sent to it: our runtime (the host's recorded measurements) serving THIS
// app (4.1, the app id) at the version the platform says runs (4.2, its code
// hash). The fleet chain and the remote quote verification come on top.
type AppPin struct {
	TEE                rc.TeeType
	MRTD, RTMR1, RTMR2 []byte // TDX
	MRENCLAVE          []byte // SGX
	AppID              []byte // 16 raw bytes (OID 4.1)
	CodeHash           []byte // 32 raw bytes (OID 4.2)
}

// PinFor builds the pin from what the control plane reports, all of it
// owner-readable: the app, its one running deployment, and that deployment's
// version. Anything missing is an error, never a looser pin:
//   - a TDX host gives MRTD, RTMR1 and RTMR2; an SGX host gives MRENCLAVE;
//   - 4.1 is the app id: a leaf without it (an app not loaded by a platform
//     deploy) is refused, and the code hash alone is never enough, since two
//     owners can deploy byte-identical code;
//   - 4.2 is the version's image manifest digest (containers) or its .cwasm
//     hash (WASM), compared as raw bytes.
func PinFor(app, deployment, version map[string]interface{}) (*AppPin, error) {
	if deployment == nil {
		return nil, errors.New("the app has no single running deployment to verify")
	}
	appID, err := uuidRaw(str(app, "id"))
	if err != nil {
		return nil, fmt.Errorf("the app id: %w", err)
	}
	p := &AppPin{AppID: appID}
	switch {
	case str(deployment, "enclave_mrtd") != "":
		p.TEE = rc.TeeTypeTDX
		for _, f := range []struct {
			field string
			dst   *[]byte
		}{{"enclave_mrtd", &p.MRTD}, {"enclave_rtmr1", &p.RTMR1}, {"enclave_rtmr2", &p.RTMR2}} {
			if *f.dst, err = hexLen(str(deployment, f.field), tdxRegisterLen); err != nil {
				return nil, fmt.Errorf("the platform's %s: %w", f.field, err)
			}
		}
	case str(deployment, "enclave_mrenclave") != "":
		p.TEE = rc.TeeTypeSGX
		if p.MRENCLAVE, err = hexLen(str(deployment, "enclave_mrenclave"), 32); err != nil {
			return nil, fmt.Errorf("the platform's enclave_mrenclave: %w", err)
		}
	default:
		return nil, errors.New("the platform gave no recorded measurement for the app's host (this platform version cannot pin it yet)")
	}
	if p.CodeHash, err = codeHash(app, version); err != nil {
		return nil, err
	}
	return p, nil
}

// codeHash is the 32-byte 4.2 value of the running version.
func codeHash(app, version map[string]interface{}) ([]byte, error) {
	if version == nil {
		return nil, errors.New("the running version could not be read")
	}
	if t := str(app, "app_type"); t == "wasm" || (t == "" && str(app, "type") == "wasm") {
		h, err := hexLen(str(version, "cwasm_hash"), 32)
		if err != nil {
			return nil, fmt.Errorf("the running version's cwasm_hash: %w", err)
		}
		return h, nil
	}
	// The digest the platform recorded for the version (its measurement set,
	// what the runtime pulled), else the one in a digest-pinned image ref. A
	// version whose ref names a tag still has its recorded digest; when both
	// are present they must agree.
	ref := str(version, "container_image")
	var recorded, inRef []byte
	if ms, _ := version["measurement_set"].(map[string]interface{}); ms != nil {
		if d := str(ms, "image_digest"); d != "" {
			h, err := hexLen(strings.TrimPrefix(d, "sha256:"), 32)
			if err != nil || !strings.HasPrefix(d, "sha256:") {
				return nil, fmt.Errorf("the running version's recorded image digest %q is not a sha256 digest", d)
			}
			recorded = h
		}
	}
	if _, digest, ok := strings.Cut(ref, "@sha256:"); ok {
		h, err := hexLen(digest, 32)
		if err != nil {
			return nil, fmt.Errorf("the running version's image digest: %w", err)
		}
		inRef = h
	}
	switch {
	case recorded != nil && inRef != nil && !bytes.Equal(recorded, inRef):
		return nil, fmt.Errorf("the running version's image %q and its recorded digest differ", ref)
	case recorded != nil:
		return recorded, nil
	case inRef != nil:
		return inRef, nil
	}
	return nil, fmt.Errorf("the running version's image %q is not pinned by digest and the platform recorded none", ref)
}

// policy is the verification policy for the pin, with the remote quote
// verification of attServerURL.
func (p *AppPin) policy(attServerURL, attServerTok string) *rc.VerificationPolicy {
	pol := &rc.VerificationPolicy{
		TEE:               p.TEE,
		QuoteVerification: &rc.QuoteVerificationConfig{Endpoint: attServerURL, Token: attServerTok},
		// Matched by exact OID: an app-installed value under another arc
		// (Mini stamps those under 5.2.{n}) can never stand in for these.
		ExpectedOids: []rc.ExpectedOid{
			{OID: rc.OidWorkloadAppID, ExpectedValue: p.AppID},
			{OID: rc.OidWorkloadCodeHash, ExpectedValue: p.CodeHash},
		},
		// AllowDebugImages stays false: a non-production image is refused.
	}
	if p.TEE == rc.TeeTypeTDX {
		pol.MRTD, pol.RTMR1, pol.RTMR2 = p.MRTD, p.RTMR1, p.RTMR2
	} else {
		pol.MRENCLAVE = p.MRENCLAVE
	}
	return pol
}

// valid reports whether the pin is complete for its TEE.
func (p *AppPin) valid() error {
	if p == nil {
		return errors.New("no pin")
	}
	if len(p.AppID) != 16 || len(p.CodeHash) != 32 {
		return errors.New("the pin lacks the app id or the code hash")
	}
	switch p.TEE {
	case rc.TeeTypeTDX:
		if len(p.MRTD) != tdxRegisterLen || len(p.RTMR1) != tdxRegisterLen || len(p.RTMR2) != tdxRegisterLen {
			return errors.New("the pin lacks a TDX measurement")
		}
	case rc.TeeTypeSGX:
		if len(p.MRENCLAVE) != 32 {
			return errors.New("the pin lacks the MRENCLAVE")
		}
	default:
		return errors.New("the pin names no TEE")
	}
	return nil
}

func hexLen(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("not %d bytes of hex", n)
	}
	return b, nil
}

func uuidRaw(s string) ([]byte, error) {
	if len(s) != 36 {
		return nil, fmt.Errorf("%q is not a UUID", s)
	}
	return hexLen(strings.ReplaceAll(s, "-", ""), 16)
}

func str(m map[string]interface{}, k string) string {
	v, _ := m[k].(string)
	return v
}
