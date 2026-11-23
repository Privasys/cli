// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package config

import "testing"

func TestPlatformAudienceFollowsTheEndpoint(t *testing.T) {
	cases := []struct {
		c    Configuration
		want string
	}{
		{Configuration{Endpoint: DefaultEndpoint}, DefaultAudience},
		{Configuration{Endpoint: TestEndpoint}, TestAudience},
		{Configuration{Endpoint: TestEndpoint + "/"}, TestAudience},
		{Configuration{Endpoint: "https://api.example.org"}, DefaultAudience},
		{Configuration{Endpoint: TestEndpoint, Audience: "custom"}, "custom"},
	}
	for _, c := range cases {
		if got := c.c.PlatformAudience(); got != c.want {
			t.Errorf("%+v: %s, want %s", c.c, got, c.want)
		}
	}
}
