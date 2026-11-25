// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// placementServer answers the three reads ResolveUpgradeTarget makes.
func placementServer(t *testing.T, deps, encs, locs interface{}) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/deployments"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"deployments": deps})
		case strings.HasSuffix(r.URL.Path, "/compatible-enclaves"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"enclaves": encs})
		case strings.HasSuffix(r.URL.Path, "/deploy-locations"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"locations": locs})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "tok")
}

type row = map[string]interface{}

func TestUpgradeTargetStaysWhereTheAppRuns(t *testing.T) {
	stopped := row{"status": "stopped", "enclave_id": "old-host"}
	cases := []struct {
		name string
		deps []row
		encs []row
		locs []row
		want DeployTarget
	}{
		{"dedicated instance", []row{stopped, {"status": "active", "enclave_id": "inst-1", "tenancy": "dedicated"}},
			[]row{{"id": "shared-1", "cloud_region_code": "europe-west9"}}, nil, DeployTarget{InstanceID: "inst-1"}},
		{"shared host, by its location", []row{{"status": "active", "enclave_id": "shared-2", "tenancy": "mutualised"}},
			[]row{{"id": "shared-1", "cloud_region_code": "europe-west1"}, {"id": "shared-2", "cloud_region_code": "europe-west9"}},
			nil, DeployTarget{Location: "europe-west9"}},
		{"shared host, region fallback", []row{{"status": "running", "enclave_id": "shared-2"}},
			[]row{{"id": "shared-2", "region": "Paris"}}, nil, DeployTarget{Location: "Paris"}},
		{"shared host not offered: named itself", []row{{"status": "active", "enclave_id": "full-host"}},
			[]row{{"id": "shared-1", "cloud_region_code": "europe-west9"}}, nil, DeployTarget{EnclaveID: "full-host"}},
		{"not running: the only location", []row{stopped}, nil,
			[]row{{"code": "europe-west9"}}, DeployTarget{Location: "europe-west9"}},
	}
	for _, c := range cases {
		got, err := placementServer(t, c.deps, c.encs, c.locs).ResolveUpgradeTarget(context.Background(), "app")
		if err != nil || got != c.want {
			t.Errorf("%s: got %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}
}

func TestUpgradeTargetAsksWhenItCannotTell(t *testing.T) {
	c := placementServer(t, nil, nil, []row{{"code": "europe-west9"}, {"code": "europe-west1"}})
	if _, err := c.ResolveUpgradeTarget(context.Background(), "app"); err == nil {
		t.Error("two locations and no running deployment gave a target")
	}
	two := []row{{"status": "active", "enclave_id": "a"}, {"status": "active", "enclave_id": "b"}}
	if CurrentDeployment(two) != nil {
		t.Error("two running deployments gave a current one")
	}
}

func TestHostEnclaveID(t *testing.T) {
	if (DeployTarget{InstanceID: "i"}).HostEnclaveID() != "i" || (DeployTarget{EnclaveID: "e"}).HostEnclaveID() != "e" ||
		(DeployTarget{Location: "l"}).HostEnclaveID() != "" {
		t.Error("HostEnclaveID")
	}
}
