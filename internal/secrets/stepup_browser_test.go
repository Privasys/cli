// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeVaultApprovalIdP answers /begin with the given deeplink (empty mimics an
// older IdP) and approves on the first /token poll.
func fakeVaultApprovalIdP(t *testing.T, deeplink string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fido2/vault-approval/begin", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"publicKey": map[string]interface{}{"challenge": "dGVzdC12YXVsdC1vcA"},
		}
		if deeplink != "" {
			resp["push_registered"] = true
			resp["approval_deeplink"] = deeplink
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("GET /fido2/vault-approval/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pageFragment runs the step-up and returns the fragment the browser page gets.
func pageFragment(t *testing.T, srv *httptest.Server) map[string]json.RawMessage {
	t.Helper()
	var opened string
	open := func(u string) error { opened = u; return nil }
	tok, err := RequestStepUpViaBrowser(context.Background(), srv.URL, "bearer", "promote",
		"apps.privasys.org/x/storage-kek/v1", "abcd", 1, nil, open, io.Discard)
	if err != nil || tok != "tok" {
		t.Fatalf("step-up = %q, %v", tok, err)
	}
	_, enc, ok := strings.Cut(opened, "#")
	if !ok {
		t.Fatalf("page URL has no fragment: %q", opened)
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("fragment is not base64url: %v", err)
	}
	var frag map[string]json.RawMessage
	if err := json.Unmarshal(raw, &frag); err != nil {
		t.Fatalf("fragment is not JSON: %v", err)
	}
	return frag
}

// TestStepUpPageCarriesWalletQR: when the IdP returns a wallet deeplink, the
// browser page must receive it and a scannable PNG of it, so the page can offer
// the wallet path when the push is late.
func TestStepUpPageCarriesWalletQR(t *testing.T) {
	const link = "privasys-wallet://vault-approvals?vault_op=dGVzdC12YXVsdC1vcA"
	frag := pageFragment(t, fakeVaultApprovalIdP(t, link))

	var gotLink, gotQR string
	_ = json.Unmarshal(frag["deeplink"], &gotLink)
	_ = json.Unmarshal(frag["qr"], &gotQR)
	if gotLink != link {
		t.Errorf("deeplink = %q, want %q", gotLink, link)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(gotQR, prefix) {
		t.Fatalf("qr = %.40q…, want a %s data URI", gotQR, prefix)
	}
	pngBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(gotQR, prefix))
	if err != nil {
		t.Fatalf("qr payload is not base64: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(pngBytes)); err != nil {
		t.Fatalf("qr payload is not a PNG: %v", err)
	}
	if len(gotQR) > 2048 {
		t.Errorf("qr data URI is %d chars; keep the page URL small", len(gotQR))
	}
}

// TestStepUpPageWithoutDeeplink: an older IdP returns no deeplink, so the page
// gets neither field and shows the passkey card alone.
func TestStepUpPageWithoutDeeplink(t *testing.T) {
	frag := pageFragment(t, fakeVaultApprovalIdP(t, ""))
	for _, k := range []string{"deeplink", "qr"} {
		if _, ok := frag[k]; ok {
			t.Errorf("fragment has %q without a deeplink from the IdP", k)
		}
	}
	if _, ok := frag["options"]; !ok {
		t.Error("fragment lost the WebAuthn options")
	}
}
