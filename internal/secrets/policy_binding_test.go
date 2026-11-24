// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"testing"

	"github.com/Privasys/enclave-vaults-client/go/vault"
)

func TestBindingVersion(t *testing.T) {
	rule := func(binding uint8, ops ...vault.Operation) vault.OperationRule {
		return vault.OperationRule{Ops: ops, Requires: []vault.Condition{{OidcStepUp: &vault.OidcStepUpCond{OperationBound: true, Binding: binding}}}}
	}
	plain := vault.OperationRule{Ops: []vault.Operation{vault.OpWrap}}
	for name, c := range map[string]struct {
		rules []vault.OperationRule
		op    vault.Operation
		want  int
		err   bool
	}{
		"v2":             {[]vault.OperationRule{rule(2, vault.OpExportKey, vault.OpDeleteKey)}, vault.OpExportKey, 2, false},
		"v1, older key":  {[]vault.OperationRule{rule(0, vault.OpExportKey)}, vault.OpExportKey, 1, false},
		"no step-up":     {[]vault.OperationRule{plain}, vault.OpWrap, 0, false},
		"another op":     {[]vault.OperationRule{rule(2, vault.OpDeleteKey)}, vault.OpExportKey, 0, false},
		"rules disagree": {[]vault.OperationRule{rule(2, vault.OpExportKey), rule(0, vault.OpExportKey)}, vault.OpExportKey, 0, true},
		"unknown":        {[]vault.OperationRule{rule(3, vault.OpExportKey)}, vault.OpExportKey, 0, true},
	} {
		got, err := BindingVersion(vault.KeyPolicy{Operations: c.rules}, c.op)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: got %d, %v", name, got, err)
		}
	}
}
