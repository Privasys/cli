// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"context"
	"strings"
	"testing"

	rc "enclave-os-mini/clients/go/ratls"
)

const testAppID = "0f8e5a2c-1b3d-4e6f-8a9b-0c1d2e3f4a5b"

func tdxDeployment() map[string]interface{} {
	return map[string]interface{}{"enclave_mrtd": strings.Repeat("11", 48),
		"enclave_rtmr1": strings.Repeat("22", 48), "enclave_rtmr2": strings.Repeat("33", 48)}
}

func TestPinForAContainerOnTDX(t *testing.T) {
	app := map[string]interface{}{"id": testAppID, "app_type": "container"}
	ver := map[string]interface{}{"container_image": "ghcr.io/o/app@sha256:" + strings.Repeat("ab", 32)}
	p, err := PinFor(app, tdxDeployment(), ver)
	if err != nil {
		t.Fatal(err)
	}
	if p.TEE != rc.TeeTypeTDX || p.MRTD[0] != 0x11 || p.RTMR2[0] != 0x33 || p.AppID[0] != 0x0f || p.CodeHash[0] != 0xab || p.valid() != nil {
		t.Errorf("pin = %+v", p)
	}
	pol := p.policy("https://as.example/verify", "att")
	if pol.QuoteVerification == nil || pol.AllowDebugImages || !bytes.Equal(pol.RTMR1, p.RTMR1) || pol.MRENCLAVE != nil {
		t.Errorf("policy = %+v", pol)
	}
	want := map[string][]byte{rc.OidWorkloadAppID: p.AppID, rc.OidWorkloadCodeHash: p.CodeHash}
	if len(pol.ExpectedOids) != 2 {
		t.Fatalf("expected OIDs = %+v", pol.ExpectedOids)
	}
	for _, e := range pol.ExpectedOids {
		if !bytes.Equal(want[e.OID], e.ExpectedValue) {
			t.Errorf("OID %s = %x", e.OID, e.ExpectedValue)
		}
	}
}

func TestPinForAWasmAppOnSGX(t *testing.T) {
	app := map[string]interface{}{"id": testAppID, "app_type": "wasm"}
	dep := map[string]interface{}{"enclave_mrenclave": strings.Repeat("44", 32)}
	ver := map[string]interface{}{"cwasm_hash": strings.Repeat("cd", 32)}
	p, err := PinFor(app, dep, ver)
	if err != nil {
		t.Fatal(err)
	}
	if p.TEE != rc.TeeTypeSGX || p.MRENCLAVE[0] != 0x44 || p.CodeHash[0] != 0xcd || p.valid() != nil {
		t.Errorf("pin = %+v", p)
	}
	if pol := p.policy("u", "t"); !bytes.Equal(pol.MRENCLAVE, p.MRENCLAVE) || pol.MRTD != nil {
		t.Errorf("policy = %+v", pol)
	}
}

// A version whose image ref names a tag is pinned by the digest the platform
// recorded for it; a recorded digest that disagrees with the ref refuses.
func TestPinForUsesTheRecordedDigestOfATaggedImage(t *testing.T) {
	app := map[string]interface{}{"id": testAppID, "app_type": "container"}
	tagged := map[string]interface{}{"container_image": "ghcr.io/o/app:v0.1.3",
		"measurement_set": map[string]interface{}{"image_digest": "sha256:" + strings.Repeat("e1", 32)}}
	p, err := PinFor(app, tdxDeployment(), tagged)
	if err != nil || p.CodeHash[0] != 0xe1 {
		t.Fatalf("pin = %+v, %v", p, err)
	}
	same := map[string]interface{}{"container_image": "r@sha256:" + strings.Repeat("e1", 32),
		"measurement_set": map[string]interface{}{"image_digest": "sha256:" + strings.Repeat("e1", 32)}}
	if _, err := PinFor(app, tdxDeployment(), same); err != nil {
		t.Errorf("agreeing ref and record refused: %v", err)
	}
	differ := map[string]interface{}{"container_image": "r@sha256:" + strings.Repeat("ab", 32),
		"measurement_set": map[string]interface{}{"image_digest": "sha256:" + strings.Repeat("e1", 32)}}
	if _, err := PinFor(app, tdxDeployment(), differ); err == nil {
		t.Error("a ref and a recorded digest that differ gave a pin")
	}
	bad := map[string]interface{}{"container_image": "r:v1",
		"measurement_set": map[string]interface{}{"image_digest": strings.Repeat("e1", 32)}}
	if _, err := PinFor(app, tdxDeployment(), bad); err == nil {
		t.Error("a recorded digest without its sha256: prefix gave a pin")
	}
}

// Anything the pin needs and the platform did not give is a refusal.
func TestPinForRefusesAnIncompletePin(t *testing.T) {
	app := map[string]interface{}{"id": testAppID, "app_type": "container"}
	ver := map[string]interface{}{"container_image": "r@sha256:" + strings.Repeat("ab", 32)}
	short := tdxDeployment()
	short["enclave_rtmr1"] = "22"
	cases := map[string]func() error{
		"no deployment":       func() error { _, err := PinFor(app, nil, ver); return err },
		"no measurement":      func() error { _, err := PinFor(app, map[string]interface{}{}, ver); return err },
		"short RTMR1":         func() error { _, err := PinFor(app, short, ver); return err },
		"no app id":           func() error { _, err := PinFor(map[string]interface{}{"app_type": "container"}, tdxDeployment(), ver); return err },
		"image by tag":        func() error { _, err := PinFor(app, tdxDeployment(), map[string]interface{}{"container_image": "r:latest"}); return err },
		"no version":          func() error { _, err := PinFor(app, tdxDeployment(), nil); return err },
		"wasm, no cwasm_hash": func() error { _, err := PinFor(map[string]interface{}{"id": testAppID, "app_type": "wasm"}, tdxDeployment(), map[string]interface{}{}); return err },
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: not refused", name)
		}
	}
}

// A call with no pin, or an incomplete one, is refused before any connection.
func TestCallRefusesWithoutAPin(t *testing.T) {
	for name, pin := range map[string]*AppPin{
		"none":    nil,
		"partial": {TEE: rc.TeeTypeTDX, AppID: make([]byte, 16), CodeHash: make([]byte, 32)},
	} {
		var out bytes.Buffer
		_, err := Call(context.Background(), CallParams{Host: "192.0.2.1", ServerName: "app.example", AppType: "container",
			AppToken: "owner", AttServerURL: "https://as.example/verify", AttServerTok: "att", Pin: pin}, &out)
		if err == nil || out.Len() != 0 {
			t.Errorf("%s: err = %v, %d bytes written", name, err, out.Len())
		}
	}
}
