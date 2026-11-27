package secrets

import (
	"testing"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

// On vaults that read every step-up as binding v2, a key with v1 rules takes
// v2; elsewhere it keeps v1. A key with no step-up asks for nothing anywhere.
func TestBindingVersionOnVaultsWithoutV1(t *testing.T) {
	owner := []vault.PrincipalRef{{Owner: true}}
	v1 := vault.KeyPolicy{Operations: []vault.OperationRule{{
		Ops: []vault.Operation{vault.OpPromoteProfile}, Principals: owner,
		Requires: []vault.Condition{{OidcStepUp: &vault.OidcStepUpCond{RequiredAmr: []string{"webauthn"}, OperationBound: true}}},
	}}}
	if b, err := BindingVersionOn(v1, vault.OpPromoteProfile, false); err != nil || b != 1 {
		t.Fatalf("older vaults: %d %v", b, err)
	}
	if b, err := BindingVersionOn(v1, vault.OpPromoteProfile, true); err != nil || b != 2 {
		t.Fatalf("vaults without v1: %d %v", b, err)
	}
	open := vault.KeyPolicy{Operations: []vault.OperationRule{{Ops: []vault.Operation{vault.OpPromoteProfile}, Principals: owner}}}
	if b, _ := BindingVersionOn(open, vault.OpPromoteProfile, true); b != 0 {
		t.Fatalf("open rule: %d", b)
	}
}
