// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"errors"
	"fmt"
)

// ErrRefused marks every refusal to send to an enclave because it could not
// be verified or pinned. errors.Is(err, ErrRefused) holds for them, whatever
// their message says, so callers classify them by kind, never by wording (a
// refusal that quotes "not found" is still a refusal, not a missing resource).
var ErrRefused = errors.New("refused to send to an unverified enclave")

// refusal is an error that is ErrRefused and also wraps its cause.
type refusal struct{ err error }

func (r *refusal) Error() string        { return r.err.Error() }
func (r *refusal) Unwrap() error        { return r.err }
func (r *refusal) Is(target error) bool { return target == ErrRefused }

// Refused formats a refusal (as fmt.Errorf, %w allowed) that is ErrRefused.
func Refused(format string, args ...interface{}) error {
	return &refusal{err: fmt.Errorf(format, args...)}
}
