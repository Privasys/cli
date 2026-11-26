// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"errors"
	"testing"
)

func TestRefusedIsErrRefusedAndKeepsItsCause(t *testing.T) {
	cause := errors.New("expected OID 1.3 not found in certificate")
	err := Refused("the manager's attestation failed, refusing to send anything: %w", cause)
	if !errors.Is(err, ErrRefused) || !errors.Is(err, cause) {
		t.Errorf("errors.Is: refused %v, cause %v", errors.Is(err, ErrRefused), errors.Is(err, cause))
	}
	if err.Error() != "the manager's attestation failed, refusing to send anything: expected OID 1.3 not found in certificate" {
		t.Errorf("message = %q", err.Error())
	}
	if !errors.Is(ErrNoQuoteVerification, ErrRefused) {
		t.Error("ErrNoQuoteVerification is not a refusal")
	}
	if errors.Is(errors.New("app not found"), ErrRefused) {
		t.Error("a plain error is a refusal")
	}
}
