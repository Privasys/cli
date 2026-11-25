// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Runtime is a TDX runtime measurement: MRTD, RTMR1 and RTMR2, lowercase hex.
type Runtime struct{ MRTD, RTMR1, RTMR2 string }

func (r Runtime) norm() Runtime {
	l := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	return Runtime{l(r.MRTD), l(r.RTMR1), l(r.RTMR2)}
}

// Equal compares two runtimes, case-insensitively.
func (r Runtime) Equal(o Runtime) bool { return r.norm() == o.norm() }

// Complete says all three values are set.
func (r Runtime) Complete() bool {
	n := r.norm()
	return n.MRTD != "" && n.RTMR1 != "" && n.RTMR2 != ""
}

// TDXRuntime reads MRTD, RTMR1 and RTMR2 from a TDX quote (v4, or v5 with a
// TD report body). Only a quote that verified may be read for a decision.
func TDXRuntime(quote []byte) (Runtime, error) {
	if len(quote) < 48 {
		return Runtime{}, errors.New("not a TDX quote")
	}
	version := binary.LittleEndian.Uint16(quote[0:2])
	if tee := binary.LittleEndian.Uint32(quote[4:8]); tee != 0x81 {
		return Runtime{}, fmt.Errorf("not a TDX quote (TEE type %#x)", tee)
	}
	body := 48
	switch version {
	case 4:
	case 5:
		// A v5 quote has a 6-byte body descriptor (type, size) after the header.
		if len(quote) < 54 {
			return Runtime{}, errors.New("truncated TDX quote")
		}
		if t := binary.LittleEndian.Uint16(quote[48:50]); t != 2 && t != 3 {
			return Runtime{}, fmt.Errorf("TDX quote body type %d is not a TD report", t)
		}
		body = 54
	default:
		return Runtime{}, fmt.Errorf("TDX quote version %d is not supported", version)
	}
	// TD report body: MRTD at 136, RTMR0 at 328, RTMR1 at 376, RTMR2 at 424.
	if len(quote) < body+424+48 {
		return Runtime{}, errors.New("truncated TDX quote")
	}
	at := func(off int) string { return hex.EncodeToString(quote[body+off : body+off+48]) }
	return Runtime{MRTD: at(136), RTMR1: at(376), RTMR2: at(424)}, nil
}

// ExpectRetireRuntime is current with every TEE profile on runtime r removed,
// whatever build it names (manager and registry-credential keys pin no image
// digest), renumbering the rules' references, and nothing else changed.
func ExpectRetireRuntime(current json.RawMessage, r Runtime) (json.RawMessage, error) {
	if !r.Complete() {
		return nil, errors.New("a runtime is named by its MRTD, RTMR1 and RTMR2")
	}
	want := r.norm()
	doc, err := decodeTree(current)
	if err != nil {
		return nil, fmt.Errorf("the key's current policy: %w", err)
	}
	root, _ := doc.(map[string]any)
	if teeRefOutsideRules(root) {
		return nil, errors.New("the key's policy refers to a TEE by position outside its operation rules")
	}
	n, err := removeTees(root, func(t any) bool {
		m, r1, r2 := teeTDX(t)
		return m == want.MRTD && r1 == want.RTMR1 && r2 == want.RTMR2
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("the key's policy has no profile on that runtime")
	}
	return json.Marshal(root)
}

// OIDWorkloadID is the X.509 OID a TEE profile pins its workload's identity
// with: the enclave id for a machine's data key, the app id for an app's key.
const OIDWorkloadID = "1.3.6.1.4.1.65230.4.1"

// KeyWorkloadID is the workload id every TEE profile of a key pins
// (OIDWorkloadID). Profiles that pin none, or different ones, are refused:
// the key could not then be tied to one machine or app.
func KeyWorkloadID(current json.RawMessage) (string, error) {
	doc, err := decodeTree(current)
	if err != nil {
		return "", fmt.Errorf("the key's current policy: %w", err)
	}
	root, _ := doc.(map[string]any)
	principals, _ := root["principals"].(map[string]any)
	tees, _ := principals["tees"].([]any)
	id := ""
	for _, t := range tees {
		m, _ := t.(map[string]any)
		prof, _ := m["Tee"].(map[string]any)
		oids, _ := prof["required_oids"].([]any)
		v := ""
		for _, o := range oids {
			om, _ := o.(map[string]any)
			if oid, _ := om["oid"].(string); oid == OIDWorkloadID {
				v, _ = om["value"].(string)
			}
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return "", errors.New("a profile of the key pins no workload id")
		}
		if id != "" && v != id {
			return "", errors.New("the key's profiles pin different workload ids")
		}
		id = v
	}
	if id == "" {
		return "", errors.New("the key has no TEE profile")
	}
	return id, nil
}

// CertCarries reports whether an attested certificate's custom OIDs (value
// as hex of its bytes) carry oid with value, given as hex or as text.
func CertCarries(oids map[string]string, oid, value string) bool {
	got, ok := oids[oid]
	if !ok {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(value))
	got = strings.ToLower(got)
	if got == want {
		return true
	}
	b, err := hex.DecodeString(got)
	return err == nil && strings.ToLower(strings.TrimSpace(string(b))) == want
}

// OIDEnclaveInstanceID is the X.509 OID a machine's manager leaf names its
// enclave with: the 16 raw bytes of the enclave id, the value its data key
// pins in OIDWorkloadID.
const OIDEnclaveInstanceID = "1.3.6.1.4.1.65230.1.3"
