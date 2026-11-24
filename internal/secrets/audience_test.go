// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

type fakeDirectory map[string]*api.VaultDirectory

func (f fakeDirectory) LiveVaultConstellations(context.Context) ([]api.LiveConstellation, error) {
	var out []api.LiveConstellation
	for id := range f {
		out = append(out, api.LiveConstellation{ID: id})
	}
	return out, nil
}

func (f fakeDirectory) VaultDirectoryAt(_ context.Context, id string) (*api.VaultDirectory, error) {
	if d, ok := f[id]; ok {
		return d, nil
	}
	return nil, errors.New("unknown")
}

func TestAudienceFor(t *testing.T) {
	dir := fakeDirectory{
		"a": {MRENCLAVE: "AA", Endpoints: []string{"h1:1", "h2:2"}, OIDCAudience: "vaults-a"},
		"b": {MRENCLAVE: "bb", Endpoints: []string{"h3:3"}, OIDCAudience: "vaults-b"},
	}
	ctx := context.Background()
	if a, err := AudienceFor(ctx, dir, []string{"h2:2", "h1:1"}, "aa"); err != nil || a != "vaults-a" {
		t.Fatalf("got %q, %v", a, err)
	}
	if a, _ := AudienceFor(ctx, dir, []string{"h1:1", "h3:3"}, "aa"); a != "" {
		t.Fatalf("endpoints of two constellations matched: %q", a)
	}
	if a, _ := AudienceFor(ctx, dir, []string{"h3:3"}, "aa"); a != "" {
		t.Fatalf("another MRENCLAVE matched: %q", a)
	}
	dir["c"] = &api.VaultDirectory{MRENCLAVE: "aa", Endpoints: []string{"h1:1"}, OIDCAudience: "other"}
	if _, err := AudienceFor(ctx, dir, []string{"h1:1"}, "aa"); err == nil {
		t.Fatal("disagreeing audiences were not refused")
	}
}
