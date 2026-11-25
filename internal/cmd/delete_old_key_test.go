// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"testing"

	"github.com/Privasys/cli/internal/api"
)

func TestCheckDeleteApproval(t *testing.T) {
	app := "31b93bdc-5810-4548-9a0e-591da7b40f7e"
	p := "apps.privasys.org/31b93bdc581045489a0e591da7b40f7e/storage-kek/"
	res := map[string]interface{}{"old_handle": p + "v1", "new_handle": p + "v2", "delete_approval": map[string]interface{}{
		"operation": "delete_after", "handle": p + "v1", "successor_handle": p + "v2", "policy_version": 4,
		"constellation_id": "aa540738", "audience": "aud", "binding_version": 2, "members": []string{"m1", "m2"},
	}}
	da, ok := api.DeleteApprovalFrom(res)
	if !ok || da.PolicyVersion != 4 || da.SuccessorHandle != p+"v2" || len(da.Members) != 2 {
		t.Fatalf("read: %+v %v", da, ok)
	}
	if err := checkDeleteApproval(app, res, da); err != nil {
		t.Fatalf("a good delete was refused: %v", err)
	}
	if _, ok := api.DeleteApprovalFrom(map[string]interface{}{"rotated": true}); ok {
		t.Fatal("an answer without delete_approval was read as one")
	}
	bad := map[string]func(d *api.DeleteApproval, r map[string]interface{}){
		"another op": func(d *api.DeleteApproval, _ map[string]interface{}) { d.Operation = "delete" },
		"binding 1":  func(d *api.DeleteApproval, _ map[string]interface{}) { d.BindingVersion = 1 },
		"another app's key": func(d *api.DeleteApproval, _ map[string]interface{}) {
			d.Handle = "apps.privasys.org/ffff/storage-kek/v1"
		},
		"another successor": func(d *api.DeleteApproval, _ map[string]interface{}) { d.SuccessorHandle = p + "v9" },
		"its own successor": func(d *api.DeleteApproval, r map[string]interface{}) {
			d.SuccessorHandle = d.Handle
			r["new_handle"] = d.Handle
		},
		"not the old handle":  func(d *api.DeleteApproval, r map[string]interface{}) { r["old_handle"] = p + "v0" },
		"no new handle given": func(_ *api.DeleteApproval, r map[string]interface{}) { delete(r, "new_handle") },
	}
	for name, mutate := range bad {
		d := *da
		r := map[string]interface{}{"old_handle": p + "v1", "new_handle": p + "v2"}
		mutate(&d, r)
		if err := checkDeleteApproval(app, r, &d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
