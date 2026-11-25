// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func fakeTDXQuote(version uint16, mrtd, r1, r2 byte) []byte {
	q := make([]byte, 48+6+584)
	binary.LittleEndian.PutUint16(q[0:2], version)
	binary.LittleEndian.PutUint32(q[4:8], 0x81)
	body := 48
	if version == 5 {
		binary.LittleEndian.PutUint16(q[48:50], 2)
		body = 54
	}
	copy(q[body+136:], bytes.Repeat([]byte{mrtd}, 48))
	copy(q[body+376:], bytes.Repeat([]byte{r1}, 48))
	copy(q[body+424:], bytes.Repeat([]byte{r2}, 48))
	return q
}

func TestTDXRuntime(t *testing.T) {
	for _, v := range []uint16{4, 5} {
		r, err := TDXRuntime(fakeTDXQuote(v, 0xaa, 0xbb, 0xcc))
		if err != nil || r.MRTD != strings.Repeat("aa", 48) || r.RTMR1 != strings.Repeat("bb", 48) || r.RTMR2 != strings.Repeat("cc", 48) {
			t.Fatalf("v%d: %+v %v", v, r, err)
		}
	}
	sgx := fakeTDXQuote(4, 1, 2, 3)
	binary.LittleEndian.PutUint32(sgx[4:8], 0)
	if _, err := TDXRuntime(sgx); err == nil {
		t.Fatal("an SGX quote was read as TDX")
	}
	if _, err := TDXRuntime(fakeTDXQuote(4, 1, 2, 3)[:300]); err == nil {
		t.Fatal("a truncated quote was read")
	}
}

func TestExpectRetireRuntime(t *testing.T) {
	// A manager key: four profiles, no image digest, one per runtime.
	p := func(m, r1, r2 string) string { return tdxTee("", m, r1, r2) }
	current := pol([]string{p("f2", "e0", "4a"), p("f2", "ca", "85"), p("f2", "ed", "a5"), p("f2", "cd", "5d")},
		`{"ops":["Unwrap"],"principals":["AnyTee"]}`)
	got, err := ExpectRetireRuntime(current, Runtime{"F2", "e0", "4A"})
	if err != nil {
		t.Fatal(err)
	}
	want := pol([]string{p("f2", "ca", "85"), p("f2", "ed", "a5"), p("f2", "cd", "5d")}, `{"ops":["Unwrap"],"principals":["AnyTee"]}`)
	if same, _ := SameStoredPolicy(bg, identityCanon, got, want); !same {
		t.Fatalf("got %s", got)
	}
	if _, err := ExpectRetireRuntime(current, Runtime{"f2", "00", "00"}); err == nil {
		t.Fatal("an absent runtime was retired")
	}
	if _, err := ExpectRetireRuntime(current, Runtime{"f2", "", "4a"}); err == nil {
		t.Fatal("an incomplete runtime was accepted")
	}
	if _, err := ExpectRetireRuntime(pol([]string{p("f2", "e0", "4a")}, ""), Runtime{"f2", "e0", "4a"}); err == nil {
		t.Fatal("the last profile was retired")
	}
}

func withID(id, m string) string {
	return `{"Tee":{"name":"v","measurements":[{"Tdx":{"mrtd":"` + m + `","rtmr1":"1","rtmr2":"2"}}],"attestation_servers":[],` +
		`"required_oids":[{"oid":"` + OIDWorkloadID + `","value":"` + id + `"}],"acceptable_tcb_statuses":null}}`
}

func TestKeyWorkloadID(t *testing.T) {
	id := "1efff2acfa6745bd9fd10c9ecbbcb9a4"
	if got, err := KeyWorkloadID(pol([]string{withID(id, "a"), withID(strings.ToUpper(id), "b")}, "")); err != nil || got != id {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := KeyWorkloadID(pol([]string{withID(id, "a"), withID("other", "b")}, "")); err == nil {
		t.Fatal("different workload ids accepted")
	}
	if _, err := KeyWorkloadID(pol([]string{tdxTee("", "a", "1", "2")}, "")); err == nil {
		t.Fatal("a profile without a workload id accepted")
	}
}

func TestCertCarries(t *testing.T) {
	id := "1efff2acfa6745bd9fd10c9ecbbcb9a4"
	asText := map[string]string{OIDWorkloadID: hex.EncodeToString([]byte(id))}
	asHex := map[string]string{OIDWorkloadID: id}
	if !CertCarries(asText, OIDWorkloadID, id) || !CertCarries(asHex, OIDWorkloadID, strings.ToUpper(id)) {
		t.Fatal("a matching id was refused")
	}
	if CertCarries(asText, OIDWorkloadID, "c7d28e2611a84905beda3944419d79cc") || CertCarries(map[string]string{}, OIDWorkloadID, id) {
		t.Fatal("another or a missing id was accepted")
	}
}
