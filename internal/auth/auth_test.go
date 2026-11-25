// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestGeneratePKCE(t *testing.T) {
	v, c := GeneratePKCE()
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if c != want {
		t.Fatalf("challenge mismatch: got %s want %s", c, want)
	}
}

func TestDeviceClientFlow(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device_authorization":
			if r.FormValue("code_challenge") == "" {
				t.Error("device_authorization missing PKCE challenge")
			}
			if r.FormValue("agent_name") != "Tester" {
				t.Errorf("agent_name not forwarded: %q", r.FormValue("agent_name"))
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code": "dev-123", "user_code": "ABCD-EFGH",
				"verification_uri": "https://privasys.id/device", "qr_payload": "https://privasys.id/scp?p=x",
				"expires_in": 600, "interval": 1,
			})
		case "/token":
			if r.FormValue("grant_type") != deviceGrantType {
				t.Errorf("wrong grant_type: %q", r.FormValue("grant_type"))
			}
			polls++
			if polls < 2 {
				json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "at-xyz", "refresh_token": "rt-xyz", "id_token": "id-xyz",
				"token_type": "Bearer", "expires_in": 900, "scope": DefaultScope,
			})
		}
	}))
	defer srv.Close()

	dr, verifier, err := BeginDevice(context.Background(), srv.URL, DefaultScope, "Tester")
	if err != nil {
		t.Fatalf("BeginDevice: %v", err)
	}
	if dr.DeviceCode != "dev-123" || dr.UserCode != "ABCD-EFGH" {
		t.Fatalf("unexpected device response: %+v", dr)
	}

	// First poll: pending.
	tr, _, err := PollOnce(context.Background(), srv.URL, dr.DeviceCode, verifier)
	if err != nil || tr != nil {
		t.Fatalf("expected pending, got tr=%v err=%v", tr, err)
	}
	// Second poll: tokens.
	tr, _, err = PollOnce(context.Background(), srv.URL, dr.DeviceCode, verifier)
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if tr.AccessToken != "at-xyz" || tr.RefreshToken != "rt-xyz" {
		t.Fatalf("unexpected tokens: %+v", tr)
	}
}

func TestDeviceClientErrors(t *testing.T) {
	for _, tc := range []struct{ srvErr, wantSubstr string }{
		{"access_denied", "denied"},
		{"expired_token", "expired"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"error": tc.srvErr})
		}))
		_, _, err := PollOnce(context.Background(), srv.URL, "d", "v")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%s: got %v", tc.srvErr, err)
		}
	}
}

func TestServiceAccountSignAndMint(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	key := &ServiceKey{Type: "serviceaccount", KeyID: "kid1", Key: string(pemBytes), UserID: "sa-1", AccountID: "sa-1"}

	// signAssertion must produce a verifiable RS256 JWT.
	assertion, err := signAssertion(key, "https://privasys.id")
	if err != nil {
		t.Fatalf("signAssertion: %v", err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion not a 3-part JWT")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("assertion signature invalid: %v", err)
	}

	// MintServiceAccountToken must POST the assertion and return the token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("grant_type") != jwtBearerGrantType {
			t.Errorf("wrong grant_type %q", r.FormValue("grant_type"))
		}
		if r.FormValue("assertion") == "" {
			t.Error("missing assertion")
		}
		if !strings.Contains(r.FormValue("scope"), "audience:privasys-platform") {
			t.Errorf("missing audience scope: %q", r.FormValue("scope"))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "sa-token", "expires_in": 900})
	}))
	defer srv.Close()
	tr, err := MintServiceAccountToken(context.Background(), srv.URL, key, "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if tr.AccessToken != "sa-token" {
		t.Fatalf("unexpected token %q", tr.AccessToken)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	keyring.MockInit() // in-memory keychain
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())

	cred := &Credential{
		Issuer: "https://privasys.id", ClientID: ClientID, Subject: "user-1",
		AccessToken: "at", RefreshToken: "rt-secret", Scope: DefaultScope,
	}
	if err := Save(cred); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load("https://privasys.id")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.RefreshToken != "rt-secret" {
		t.Fatalf("refresh token not rehydrated: %q", got.RefreshToken)
	}
	if got.Subject != "user-1" {
		t.Fatalf("subject = %q", got.Subject)
	}

	// The refresh token must NOT be in the plaintext file (kept in keychain).
	data, _ := readCredsFile(t)
	if strings.Contains(data, "rt-secret") {
		t.Errorf("refresh token leaked into the credentials file")
	}

	if err := Delete("https://privasys.id"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Load("https://privasys.id"); err == nil {
		t.Fatalf("expected ErrNotLoggedIn after delete")
	}
}

func TestClaims(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-9","roles":["privasys-platform:admin"]}`))
	m, err := Claims("h." + payload + ".s")
	if err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if m["sub"] != "user-9" {
		t.Fatalf("sub = %v", m["sub"])
	}
}

func readCredsFile(t *testing.T) (string, error) {
	t.Helper()
	p, err := credentialsPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	return string(b), err
}


// Each platform has its own sign-in: a test-platform token never comes from
// the production sign-in (the IdP refuses that refresh, and it must never be
// asked), and the two are stored and refreshed apart.
func TestEachPlatformHasItsOwnSignIn(t *testing.T) {
	keyring.MockInit()
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())
	t.Setenv("PRIVASYS_ACCESS_TOKEN", "")
	t.Setenv("PRIVASYS_SERVICE_KEY", "")
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		asked = append(asked, r.PostForm.Get("refresh_token")+" "+r.PostForm.Get("scope"))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token-2", "refresh_token": "rt-test-2", "expires_in": 3600,
		})
	}))
	defer srv.Close()
	defer SetPlatformAudience("")

	// Only a production sign-in: the test platform has none, and nothing is asked.
	if err := Save(&Credential{Issuer: srv.URL, AccessToken: "prod-token",
		AccessExpiresAt: time.Now().Add(time.Hour), RefreshToken: "rt-prod"}); err != nil {
		t.Fatal(err)
	}
	SetPlatformAudience("privasys-platform-test")
	if _, err := AccessToken(context.Background(), srv.URL); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("test platform without its sign-in: err = %v, want ErrNotLoggedIn", err)
	}
	if len(asked) != 0 {
		t.Fatalf("a cross-platform refresh was asked: %q", asked)
	}

	// A test-platform sign-in (expired): refreshed with its own token and audience.
	if err := Save(&Credential{Issuer: srv.URL, Platform: "privasys-platform-test", AccessToken: "test-token-1",
		AccessExpiresAt: time.Now().Add(-time.Hour), RefreshToken: "rt-test-1"}); err != nil {
		t.Fatal(err)
	}
	tok, err := AccessToken(context.Background(), srv.URL)
	if err != nil || tok != "test-token-2" {
		t.Fatalf("test platform: %q, %v", tok, err)
	}
	if len(asked) != 1 || asked[0] != "rt-test-1 openid audience:privasys-platform-test" {
		t.Errorf("refreshes: %q, want the test sign-in's own token and audience", asked)
	}
	test, _ := LoadFor(srv.URL, "privasys-platform-test")
	prod, _ := LoadFor(srv.URL, "privasys-platform")
	if test.RefreshToken != "rt-test-2" || prod.RefreshToken != "rt-prod" {
		t.Errorf("rotation crossed sign-ins: test %q, prod %q", test.RefreshToken, prod.RefreshToken)
	}

	// Production is untouched and served from its own cache.
	SetPlatformAudience("")
	if tok, err := AccessToken(context.Background(), srv.URL); err != nil || tok != "prod-token" {
		t.Errorf("production: %q, %v", tok, err)
	}
	// A vault audience that is a platform's comes from that platform's sign-in.
	if _, err := AccessTokenForAudience(context.Background(), srv.URL, "privasys-platform-test"); err != nil {
		t.Fatal(err)
	}
	if got := asked[len(asked)-1]; got != "rt-test-2 openid audience:privasys-platform-test" {
		t.Errorf("test vault audience refreshed with %q", got)
	}
}

func TestCredentialLockSerialises(t *testing.T) {
	t.Setenv("PRIVASYS_CONFIG_DIR", t.TempDir())
	var mu sync.Mutex
	inside, maxInside := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withCredentialLock(func() error {
				mu.Lock()
				inside++
				if inside > maxInside {
					maxInside = inside
				}
				mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				mu.Lock()
				inside--
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("%d holders at once", maxInside)
	}
}
