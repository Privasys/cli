// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mockwallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestParseQRPayload(t *testing.T) {
	qr := map[string]string{"origin": "privasys.id", "sessionId": "sess-abc", "rpId": "privasys.id"}
	raw, _ := json.Marshal(qr)
	link := "https://privasys.id/scp?p=" + base64.RawURLEncoding.EncodeToString(raw)

	info, err := parseQRPayload(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.SessionID != "sess-abc" || info.RpID != "privasys.id" || info.Origin != "https://privasys.id" {
		t.Fatalf("parsed %+v", info)
	}
	if _, err := parseQRPayload("https://privasys.id/scp"); err == nil {
		t.Error("expected error for a payload with no 'p'")
	}
}

// --- A faithful in-process IdP backed by the real go-webauthn server lib,
// wired like the Privasys IdP (session_id binding + device store), so the
// wallet's full ceremony glue is exercised with no network. ---

type testUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *testUser) WebAuthnID() []byte                         { return u.id }
func (u *testUser) WebAuthnName() string                       { return u.name }
func (u *testUser) WebAuthnDisplayName() string                { return u.name }
func (u *testUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type testIdP struct {
	*httptest.Server
	wa       *webauthn.WebAuthn
	userCode string
	session  string

	mu       sync.Mutex
	pending  map[string]*ceremony // keyed by base64url(challenge)
	approved map[string]bool      // session id -> authenticated
}

type ceremony struct {
	sess    *webauthn.SessionData
	user    *testUser
	session string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          "privasys.id",
		RPDisplayName: "Privasys",
		RPOrigins:     []string{"https://privasys.id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{
		wa:       wa,
		userCode: "WXYZ-1234",
		session:  "sess-1",
		pending:  map[string]*ceremony{},
		approved: map[string]bool{},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/device/lookup", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("user_code") != idp.userCode {
			http.Error(w, "unknown code", http.StatusNotFound)
			return
		}
		qr, _ := json.Marshal(map[string]string{"origin": "privasys.id", "sessionId": idp.session, "rpId": "privasys.id"})
		_ = json.NewEncoder(w).Encode(map[string]string{
			"qr_payload": "https://privasys.id/scp?p=" + base64.RawURLEncoding.EncodeToString(qr),
			"status":     "pending",
		})
	})

	mux.HandleFunc("/fido2/register/begin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserName   string `json:"userName"`
			UserHandle string `json:"userHandle"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		uh, _ := base64.RawURLEncoding.DecodeString(req.UserHandle)
		user := &testUser{id: uh, name: req.UserName}

		creation, sess, err := idp.wa.BeginRegistration(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		idp.mu.Lock()
		// SessionData.Challenge is already the base64url string the wallet
		// echoes back as ?challenge= on complete.
		idp.pending[sess.Challenge] = &ceremony{
			sess: sess, user: user, session: r.URL.Query().Get("session_id"),
		}
		idp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(creation) // {"publicKey":{...}}
	})

	mux.HandleFunc("/fido2/register/complete", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		c, ok := idp.pending[r.URL.Query().Get("challenge")]
		idp.mu.Unlock()
		if !ok {
			http.Error(w, "unknown challenge", http.StatusBadRequest)
			return
		}
		cred, err := idp.wa.FinishRegistration(c.user, *c.sess, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c.user.creds = append(c.user.creds, *cred)
		idp.mu.Lock()
		idp.approved[c.session] = true
		idp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "sessionToken": "tok", "userId": c.user.name})
	})

	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func TestApproveDeviceAgainstGoWebauthn(t *testing.T) {
	idp := newTestIdP(t)
	w := New()

	if err := w.ApproveDevice(context.Background(), idp.URL, idp.userCode); err != nil {
		t.Fatalf("ApproveDevice: %v", err)
	}
	idp.mu.Lock()
	approved := idp.approved[idp.session]
	idp.mu.Unlock()
	if !approved {
		t.Fatal("device session was not authenticated by the wallet ceremony")
	}
}

// TestLiveDeviceApprove runs the wallet against a REAL IdP. Skipped unless
// PRIVASYS_E2E_IDP (issuer origin) and PRIVASYS_E2E_USER_CODE are set — the
// live L3 harness wires these up around a real `auth begin`.
func TestLiveDeviceApprove(t *testing.T) {
	idpURL := os.Getenv("PRIVASYS_E2E_IDP")
	userCode := os.Getenv("PRIVASYS_E2E_USER_CODE")
	if idpURL == "" || userCode == "" {
		t.Skip("set PRIVASYS_E2E_IDP and PRIVASYS_E2E_USER_CODE to run the live device-approve test")
	}
	if err := New().ApproveDevice(context.Background(), idpURL, userCode); err != nil {
		t.Fatalf("live ApproveDevice: %v", err)
	}
}
