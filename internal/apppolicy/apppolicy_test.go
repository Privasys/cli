package apppolicy

// What an operator is told about the policy an app is enforcing. The stale
// case is the one that matters: it is how a restored /data, or a document that
// never reached the app, becomes visible.

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Privasys/cli/internal/ratls"
)

func stamp(seq uint64, digestHex string) *ratls.Result {
	raw := make([]byte, 8, 40)
	binary.BigEndian.PutUint64(raw, seq)
	d, _ := hex.DecodeString(digestHex)
	raw = append(raw, d...)
	return &ratls.Result{CustomOIDs: []ratls.OID{{
		OID:      OIDAttestedAppPolicy,
		Label:    "Attested App Policy",
		ValueHex: hex.EncodeToString(raw),
	}}}
}

const digestA = "aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899"
const digestB = "bb11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899"

func TestPolicyFromResult(t *testing.T) {
	got, ok := FromResult(stamp(7, digestA))
	if !ok {
		t.Fatal("the stamp was not read")
	}
	if got.Seq != 7 || got.Digest != digestA {
		t.Fatalf("seq=%d digest=%s", got.Seq, got.Digest)
	}
	if _, ok := FromResult(&ratls.Result{}); ok {
		t.Error("an app with no stamp reported one")
	}
	// A truncated value is not a policy: better to report none than to show
	// a number read out of the wrong bytes.
	bad := &ratls.Result{CustomOIDs: []ratls.OID{{OID: OIDAttestedAppPolicy, ValueHex: "0011"}}}
	if _, ok := FromResult(bad); ok {
		t.Error("a malformed stamp was accepted")
	}
}

func TestPolicyStatusWording(t *testing.T) {
	att, _ := FromResult(stamp(7, digestA))
	cases := []struct {
		name      string
		att       Attested
		attested  bool
		seq       uint64
		digest    string
		expectStr string
	}{
		{"in force", att, true, 7, digestA, "enforcing the approved policy"},
		{"stale", att, true, 9, digestB, "STALE policy"},
		{"never installed", Attested{}, false, 4, digestA, "NOT ENFORCING"},
		{"none anywhere", Attested{}, false, 0, "", "no owner-approved policy"},
		{"nothing to compare", att, true, 0, "", "the platform holds none"},
		{"ahead", att, true, 5, digestB, "AHEAD"},
		{"same seq, other document", att, true, 7, digestB, "the document differs"},
	}
	for _, c := range cases {
		got := Status(c.att, c.attested, c.seq, c.digest)
		if !strings.Contains(got, c.expectStr) {
			t.Errorf("%s: %q does not mention %q", c.name, got, c.expectStr)
		}
	}
}
