package cmd

// Reading the policy an app is enforcing out of its attestation.
//
// The runtime stamps the owner-approved policy it installed into the app's
// certificate: the document's sequence number and its SHA-256. That is what
// makes a stale policy visible. A host that restored an older /data, or a
// document that never reached the app, both show up here as a sequence behind
// the one the platform holds.
//
// Checking it is the point: the value is on the wire either way, but nobody
// benefits until something compares it with what the owner last approved.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/ratls"
)

// oidAttestedAppPolicy mirrors ratls.OidAttestedAppPolicy in the SDK (7.2 is
// reserved for allowed callers, so the policy stamp is 7.3).
const oidAttestedAppPolicy = "1.3.6.1.4.1.65230.7.3"

// attestedPolicy is what an app's certificate says about the policy in force.
type attestedPolicy struct {
	Seq    uint64
	Digest string
}

// policyFromResult extracts the policy stamp, reporting whether the app
// advertises one at all. An app whose owner has approved no policy carries no
// stamp, which is not a fault.
func policyFromResult(r *ratls.Result) (attestedPolicy, bool) {
	for _, o := range r.CustomOIDs {
		if o.OID != oidAttestedAppPolicy {
			continue
		}
		raw, err := hex.DecodeString(o.ValueHex)
		if err != nil || len(raw) != 40 {
			return attestedPolicy{}, false
		}
		return attestedPolicy{
			Seq:    binary.BigEndian.Uint64(raw[:8]),
			Digest: hex.EncodeToString(raw[8:]),
		}, true
	}
	return attestedPolicy{}, false
}

// policyStatus compares the policy an app enforces with the one the platform
// holds for it, and returns a line to show the operator.
//
// stored is what the platform was given (seq and the document digest); either
// may be zero-valued when the platform holds none.
func policyStatus(att attestedPolicy, attested bool, storedSeq uint64, storedDigest string) string {
	switch {
	case !attested && storedSeq == 0:
		return "no owner-approved policy: this app's policy still comes from the platform"
	case !attested:
		return fmt.Sprintf("NOT ENFORCING the approved policy: the platform holds seq %d, the app advertises none", storedSeq)
	case storedSeq == 0:
		return fmt.Sprintf("enforcing policy seq %d (%s); the platform holds none to compare", att.Seq, short(att.Digest))
	case att.Seq == storedSeq && strings.EqualFold(att.Digest, storedDigest):
		return fmt.Sprintf("enforcing the approved policy, seq %d (%s)", att.Seq, short(att.Digest))
	case att.Seq < storedSeq:
		return fmt.Sprintf("STALE policy: enforcing seq %d, the owner approved seq %d; redeploy or re-send the policy", att.Seq, storedSeq)
	case att.Seq > storedSeq:
		return fmt.Sprintf("enforcing seq %d, which is AHEAD of the seq %d the platform holds", att.Seq, storedSeq)
	default:
		return fmt.Sprintf("policy seq %d matches, but the document differs: enforcing %s, approved %s", att.Seq, short(att.Digest), short(storedDigest))
	}
}

func short(hexStr string) string {
	if len(hexStr) <= 12 {
		return hexStr
	}
	return hexStr[:12] + "…"
}

// storedPolicy reads the seq and document digest the platform holds for an
// app. Best-effort: an app with no approved policy, or a platform that cannot
// be reached, simply gives nothing to compare with.
func storedPolicy(ctx context.Context, client *api.Client, appID string) (uint64, string) {
	out, err := client.GetAppPolicy(ctx, appID)
	if err != nil || out == nil {
		return 0, ""
	}
	seqF, _ := out["seq"].(float64)
	doc, _ := json.Marshal(out["document"])
	if len(doc) == 0 || string(doc) == "null" {
		return uint64(seqF), ""
	}
	sum := sha256.Sum256(doc)
	return uint64(seqF), hex.EncodeToString(sum[:])
}
