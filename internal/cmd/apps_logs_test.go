// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLogsTargetNeedsTheManagerFromThePlatform(t *testing.T) {
	app := map[string]interface{}{"name": "my-app"}
	cur := map[string]interface{}{"enclave_id": "0f8e5a2c-1b3d-4e6f-8a9b-0c1d2e3f4a5b",
		"manager_hostname": "eu-france-1-mgr.apps.example", "gateway_host": "203.0.113.7", "manager_port": float64(8443),
		"enclave_mrtd": strings.Repeat("11", 48), "enclave_rtmr1": strings.Repeat("22", 48), "enclave_rtmr2": strings.Repeat("33", 48)}
	w, err := logsTarget(app, cur)
	if err != nil {
		t.Fatal(err)
	}
	if w.manager != "eu-france-1-mgr.apps.example" || w.dial != "203.0.113.7" || w.port != 8443 || w.container != "my-app" || len(w.enclaveID) != 16 || w.enclaveID[0] != 0x0f ||
		len(w.mrtd) != 48 || w.rtmr1[0] != 0x22 || w.rtmr2[0] != 0x33 {
		t.Errorf("target = %+v", w)
	}
	if _, err := logsTarget(app, nil); err == nil {
		t.Error("no running deployment gave a target")
	}
	for _, drop := range []string{"manager_hostname", "gateway_host", "manager_port", "enclave_mrtd", "enclave_rtmr1", "enclave_rtmr2"} {
		c := map[string]interface{}{}
		for k, v := range cur {
			if k != drop {
				c[k] = v
			}
		}
		if _, err := logsTarget(app, c); err == nil {
			t.Errorf("a deployment without %s gave a target", drop)
		}
	}
	bad := map[string]interface{}{"enclave_id": "not-a-uuid", "manager_hostname": "m", "gateway_host": "g"}
	if _, err := logsTarget(app, bad); err == nil {
		t.Error("a bad enclave id gave a target")
	}
}

func TestPlainPlatformBearerRefusesAnApproval(t *testing.T) {
	jwt := func(claims string) string {
		e := base64.RawURLEncoding.EncodeToString
		return e([]byte(`{"alg":"none"}`)) + "." + e([]byte(claims)) + ".sig"
	}
	if err := plainPlatformBearer(jwt(`{"sub":"o","aud":"privasys-platform"}`)); err != nil {
		t.Errorf("a plain token was refused: %v", err)
	}
	if err := plainPlatformBearer(jwt(`{"sub":"o","vault_op":"x"}`)); err == nil {
		t.Error("a token with vault_op was accepted")
	}
}

func TestLogsStatus(t *testing.T) {
	if logsStatus(200) != nil {
		t.Error("200")
	}
	if err := logsStatus(403); err == nil || !strings.Contains(err.Error(), "only the app's owner") {
		t.Errorf("403: %v", err)
	}
	if err := logsStatus(404); err == nil || err.Error() != "nothing captured yet" {
		t.Errorf("404: %v", err)
	}
}
