// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

func profileTestOID(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatal(err)
		}
		oid = append(oid, n)
	}
	return oid
}

func profileTestLeaf(t *testing.T, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mgr"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The manager leaf must carry the image profile, and it must be "production":
// a leaf without it is refused on this path even though the verifier alone
// would accept it.
func TestManagerPolicyRequiresAProductionProfile(t *testing.T) {
	p := validManagerParams()
	pol, err := managerPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	id := pkix.Extension{Id: profileTestOID(t, rc.OidEnclaveInstanceID), Value: p.EnclaveID}
	profile := func(v string) pkix.Extension {
		return pkix.Extension{Id: profileTestOID(t, rc.OidImageProfile), Value: []byte(v)}
	}
	cases := []struct {
		name string
		exts []pkix.Extension
		ok   bool
	}{
		{"production", []pkix.Extension{profile("production"), id}, true},
		{"no profile", []pkix.Extension{id}, false},
		{"dev", []pkix.Extension{profile("dev"), id}, false},
		{"padded", []pkix.Extension{profile("production "), id}, false},
		{"empty", []pkix.Extension{profile(""), id}, false},
	}
	for _, c := range cases {
		_, err := rc.VerifyCertificateExtensions(profileTestLeaf(t, c.exts), pol)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
