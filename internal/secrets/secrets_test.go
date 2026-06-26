// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserKeyPolicyJSON(t *testing.T) {
	raw := userKeyPolicyJSON("https://privasys.id", "user-1", true)
	var p map[string]interface{}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("policy not valid JSON: %v", err)
	}
	owner := p["principals"].(map[string]interface{})["owner"].(map[string]interface{})["Oidc"].(map[string]interface{})
	if owner["issuer"] != "https://privasys.id" || owner["sub"] != "user-1" {
		t.Fatalf("owner principal = %v", owner)
	}
	ops := p["operations"].([]interface{})[0].(map[string]interface{})
	if got := ops["principals"].([]interface{})[0]; got != "Owner" {
		t.Fatalf("operation principal = %v, want \"Owner\"", got)
	}
	foundExport := false
	for _, o := range ops["ops"].([]interface{}) {
		if o == "ExportKey" {
			foundExport = true
		}
	}
	if !foundExport {
		t.Error("exportable policy should grant the owner ExportKey")
	}
	if im := p["mutability"].(map[string]interface{})["immutable"].([]interface{})[0]; im != "Owner" {
		t.Errorf("owner principal must be immutable, got %v", im)
	}

	// A non-exportable policy must not grant ExportKey.
	var p2 map[string]interface{}
	_ = json.Unmarshal(userKeyPolicyJSON("https://privasys.id", "u", false), &p2)
	for _, o := range p2["operations"].([]interface{})[0].(map[string]interface{})["ops"].([]interface{}) {
		if o == "ExportKey" {
			t.Error("non-exportable policy must not grant ExportKey")
		}
	}
}

func TestGenerateClientCert(t *testing.T) {
	cert, cnf, err := generateClientCert("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("want one cert in the chain, got %d", len(cert.Certificate))
	}
	sum := sha256.Sum256(cert.Certificate[0])
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); cnf != want {
		t.Fatalf("thumbprint mismatch:\n got %s\nwant %s", cnf, want)
	}
}

func TestRequestGrant(t *testing.T) {
	var gotBody grantRequest
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != grantPath {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{"grant": "the.grant.jwt"})
	}))
	defer srv.Close()

	p := CreateParams{Issuer: srv.URL, Bearer: "user-bearer", Sub: "user-1", Exportable: true}
	grant, err := requestGrant(context.Background(), p, "thumb-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if grant != "the.grant.jwt" {
		t.Fatalf("grant = %q", grant)
	}
	if gotAuth != "Bearer user-bearer" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotBody.Scope != "users/user-1" {
		t.Errorf("scope = %q, want users/user-1", gotBody.Scope)
	}
	if gotBody.KeyType != "RawShare" {
		t.Errorf("key_type = %q", gotBody.KeyType)
	}
	if gotBody.CnfX5tS256 != "thumb-xyz" {
		t.Errorf("cnf = %q (holder-of-key binding must be sent)", gotBody.CnfX5tS256)
	}
	if len(gotBody.Policy) == 0 {
		t.Error("policy must be sent")
	}
}
