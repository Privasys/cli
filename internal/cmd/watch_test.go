// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import "testing"

func TestDeployPhase(t *testing.T) {
	cases := []struct {
		status, container string
		wantLabel         string
		wantDone          bool
		wantFailed        bool
	}{
		{"starting", "unknown", "preparing", false, false},
		{"starting", "", "preparing", false, false},
		{"starting", "pulling", "pulling image", false, false},
		{"starting", "running", "starting container", false, false},
		{"active", "running", "active", true, false},
		{"deployed", "running", "active", true, false},
		{"failed", "pulling", "failed", true, true},
		{"error", "", "error", true, true},
		{"stopped", "running", "stopped", true, true},
	}
	for _, c := range cases {
		label, done, failed := deployPhase(c.status, c.container)
		if label != c.wantLabel || done != c.wantDone || failed != c.wantFailed {
			t.Errorf("deployPhase(%q,%q) = (%q,%v,%v); want (%q,%v,%v)",
				c.status, c.container, label, done, failed, c.wantLabel, c.wantDone, c.wantFailed)
		}
	}
}
