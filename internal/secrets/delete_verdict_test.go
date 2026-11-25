// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

func TestDeleteVerdict(t *testing.T) {
	notFound := &vault.ErrVaultError{Message: "key not found"}
	tomb := &vault.ErrVaultError{Message: "key deleted at 1 (delete); successor -; the handle is reusable after 2"}
	refused := &vault.ErrVaultError{Message: "caller is not in policy.principals"}
	dialErr := errors.New("dial tcp: connection refused")
	looksNotFound := errors.New("approval rule not found")
	held := error(nil)
	cases := []struct {
		name    string
		ms      []memberDelete
		ok      bool
		missing bool // ErrKeyNotFound
	}{
		{"deleted on both, gone on both", []memberDelete{
			{Endpoint: "a", Asked: true, Read: true, ReadErr: notFound},
			{Endpoint: "b", Asked: true, Read: true, ReadErr: notFound}}, true, false},
		{"tombstones: deleted again idempotently", []memberDelete{
			{Endpoint: "a", Asked: true, DelErr: tomb, Read: true, ReadErr: tomb},
			{Endpoint: "b", Asked: true, DelErr: tomb, Read: true, ReadErr: tomb}}, true, false},
		{"whole key on one member", []memberDelete{
			{Endpoint: "a", Asked: true, Read: true, ReadErr: notFound},
			{Endpoint: "b", Asked: true, DelErr: notFound, Read: true, ReadErr: notFound}}, true, false},
		{"every member says not found: never silent success", []memberDelete{
			{Endpoint: "a", Asked: true, DelErr: notFound, Read: true, ReadErr: notFound},
			{Endpoint: "b", Asked: true, DelErr: notFound, Read: true, ReadErr: notFound}}, false, true},
		{"not found on delete, but still held on read-back", []memberDelete{
			{Endpoint: "a", Asked: true, DelErr: notFound, Read: true, ReadErr: held},
			{Endpoint: "b", Asked: true, Read: true, ReadErr: notFound}}, false, false},
		{"a refusal is not gone", []memberDelete{
			{Endpoint: "a", Asked: true, DelErr: refused, Read: true, ReadErr: held}}, false, false},
		{"a message containing not found is not gone", []memberDelete{
			{Endpoint: "a", Asked: true, DelErr: looksNotFound, Read: true, ReadErr: looksNotFound}}, false, false},
		{"deleted on one, other unreachable", []memberDelete{
			{Endpoint: "a", Asked: true, Read: true, ReadErr: notFound},
			{Endpoint: "b", DelErr: dialErr, ReadErr: dialErr}}, false, false},
		{"nothing reached", []memberDelete{
			{Endpoint: "a", DelErr: dialErr, ReadErr: dialErr}}, false, false},
		{"no members at all", nil, false, true},
	}
	for _, c := range cases {
		_, err := deleteVerdict("h", c.ms)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if c.missing != errors.Is(err, ErrKeyNotFound) {
			t.Errorf("%s: ErrKeyNotFound = %v, err %v", c.name, !c.missing, err)
		}
	}
}

func TestKeyGoneIsExact(t *testing.T) {
	if g, _ := keyGone(errors.New("rule not found")); g {
		t.Error("a message containing not found counted as gone")
	}
	if g, _ := keyGone(&vault.ErrVaultError{Message: "key not found"}); !g {
		t.Error("the vault's key not found did not count")
	}
	if g, d := keyGone(&vault.ErrVaultError{Message: "key deleted at 1 (delete)"}); !g || !d {
		t.Error("a tombstone did not count as deleted")
	}
}

func TestSameStoredPolicyNeedsNoVaultWhenEqual(t *testing.T) {
	a := []byte(`{"b":1,"a":{"y":2,"x":[1,2]}}`)
	b := []byte(`{"a":{"x":[1,2],"y":2},"b":1}`)
	unsupported := func(context.Context, json.RawMessage) (json.RawMessage, error) {
		return nil, fmt.Errorf("the vault v refuses the policy: %w", vault.ErrUnsupported)
	}
	same, err := SameStoredPolicy(context.Background(), unsupported, a, b)
	if err != nil || !same {
		t.Fatalf("equal policies in another key order: same=%v err=%v", same, err)
	}
	_, err = SameStoredPolicy(context.Background(), unsupported, a, []byte(`{"b":2}`))
	if !errors.Is(err, ErrCannotConfirm) {
		t.Fatalf("a difference on an old build: err=%v, want ErrCannotConfirm", err)
	}
}
