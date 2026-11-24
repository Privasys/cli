// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/Privasys/cli/internal/api"
)

func twoGenerations() []SecretCopy {
	a := &api.VaultDirectory{Name: "dev-v0.43.0"}
	b := &api.VaultDirectory{Name: "dev-v0.42.0"}
	c := []SecretCopy{
		{Handle: "users/s/x", Gen: 1, Dir: b},
		{Handle: "users/s/x/gen-2", Gen: 2, Dir: a},
	}
	sortNewestFirst(c)
	return c
}

func TestRemoveSecretCopiesDeletesEveryGenerationNewestFirst(t *testing.T) {
	copies := twoGenerations()
	if copies[0].Gen != 2 || copies[1].Gen != 1 {
		t.Fatalf("not newest first: %+v", copies)
	}
	var order []string
	res, err := RemoveSecretCopies(context.Background(), copies, func(_ context.Context, c SecretCopy) error {
		order = append(order, c.Handle)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "users/s/x/gen-2" || order[1] != "users/s/x" {
		t.Fatalf("delete order: %v", order)
	}
	for _, r := range res {
		if !r.Deleted || !r.Attempted {
			t.Fatalf("not deleted: %+v", r)
		}
	}
}

func TestRemoveSecretCopiesStopsAtADecline(t *testing.T) {
	calls := 0
	res, err := RemoveSecretCopies(context.Background(), twoGenerations(), func(context.Context, SecretCopy) error {
		calls++
		return ErrDeclined
	})
	if !errors.Is(err, ErrDeclined) || calls != 1 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
	if res[0].Deleted || res[1].Attempted || res[1].Deleted {
		t.Fatalf("results: %+v", res)
	}
}

func TestRemoveSecretCopiesGoesOnAfterAFailure(t *testing.T) {
	res, err := RemoveSecretCopies(context.Background(), twoGenerations(), func(_ context.Context, c SecretCopy) error {
		if c.Gen == 2 {
			return errors.New("vault unreachable")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Deleted || res[0].Err == nil || !res[1].Deleted {
		t.Fatalf("results: %+v", res)
	}
}
