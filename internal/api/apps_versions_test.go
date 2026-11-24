// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import "testing"

// The control plane lists versions newest first; the newest is chosen by
// number, never by position.
func TestNewestVersionID(t *testing.T) {
	for name, c := range map[string]struct {
		vs   []map[string]interface{}
		want string
	}{
		"newest first": {[]map[string]interface{}{{"id": "c", "version_number": 3.0}, {"id": "b", "version_number": 2.0}, {"id": "a", "version_number": 1.0}}, "c"},
		"oldest first": {[]map[string]interface{}{{"id": "a", "version_number": 1.0}, {"id": "c", "version_number": 3.0}}, "c"},
		"as strings":   {[]map[string]interface{}{{"id": "a", "version_number": "9"}, {"id": "b", "version_number": "10"}}, "b"},
		"no numbers":   {[]map[string]interface{}{{"id": "a"}}, ""},
		"none":         {nil, ""},
	} {
		if got := NewestVersionID(c.vs); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}
