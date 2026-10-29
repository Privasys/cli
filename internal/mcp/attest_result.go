// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import "github.com/Privasys/cli/internal/ratls"

// attestResult is the attest tool's answer: the verification itself, with the
// policy verdict alongside. The embedded Result keeps its own JSON fields.
type attestResult struct {
	*ratls.Result
	Policy *policyVerdict `json:"policy,omitempty"`
}

// policyVerdict compares the policy an app's certificate says it enforces with
// the one its owner last approved (as the platform holds it).
type policyVerdict struct {
	Advertised     bool   `json:"advertised"`
	Seq            uint64 `json:"seq,omitempty"`
	Digest         string `json:"digest,omitempty"`
	ApprovedSeq    uint64 `json:"approved_seq,omitempty"`
	ApprovedDigest string `json:"approved_digest,omitempty"`
	Status         string `json:"status"`
}
