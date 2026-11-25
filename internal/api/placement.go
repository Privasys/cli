// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"fmt"
)

// DeployTarget is where a deploy goes: one of an instance, a location, or an
// enclave (an explicit override, or the app's own host when its location
// cannot be read).
type DeployTarget struct {
	EnclaveID, Location, InstanceID string
}

// HostEnclaveID is the enclave the target runs on, when it is known before the
// deploy (an instance's enclave id is its instance id).
func (t DeployTarget) HostEnclaveID() string {
	if t.EnclaveID != "" {
		return t.EnclaveID
	}
	return t.InstanceID
}

// CurrentDeployment is the app's one running deployment that names its host,
// or nil when there is none or more than one.
func CurrentDeployment(deps []map[string]interface{}) map[string]interface{} {
	var cur map[string]interface{}
	for _, d := range deps {
		switch str(d, "status") {
		case "active", "deployed", "running":
			if str(d, "enclave_id") == "" {
				continue
			}
			if cur != nil {
				return nil
			}
			cur = d
		}
	}
	return cur
}

// ResolveUpgradeTarget keeps an upgrade where the app runs now. It never moves
// a running app to another host on its own:
//   - an app on a dedicated instance goes back to that instance;
//   - an app on a shared host is deployed by that host's location, which the
//     server pins to the same host; when the host's location cannot be read,
//     the host itself is named, which the server accepts for the app's own
//     active host;
//   - an app with no running deployment uses the only location offered.
func (c *Client) ResolveUpgradeTarget(ctx context.Context, appID string) (DeployTarget, error) {
	deps, err := c.ListDeployments(ctx, appID)
	if err != nil {
		return DeployTarget{}, err
	}
	if cur := CurrentDeployment(deps); cur != nil {
		host := str(cur, "enclave_id")
		if str(cur, "tenancy") == "dedicated" {
			return DeployTarget{InstanceID: host}, nil
		}
		encs, err := c.CompatibleEnclaves(ctx, appID)
		if err != nil {
			return DeployTarget{}, err
		}
		for _, e := range encs {
			if str(e, "id") != host {
				continue
			}
			if code := enclaveLocationCode(e); code != "" {
				return DeployTarget{Location: code}, nil
			}
		}
		return DeployTarget{EnclaveID: host}, nil
	}
	locs, err := c.DeployLocations(ctx, appID)
	if err != nil {
		return DeployTarget{}, err
	}
	if len(locs) != 1 {
		return DeployTarget{}, fmt.Errorf("the app is not running and %d locations are available: name the location (see `privasys apps locations`)", len(locs))
	}
	return DeployTarget{Location: str(locs[0], "code")}, nil
}

// enclaveLocationCode is the location code the platform gives a host: its
// cloud region code, else its region.
func enclaveLocationCode(e map[string]interface{}) string {
	if code := str(e, "cloud_region_code"); code != "" {
		return code
	}
	return str(e, "region")
}

func str(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}
