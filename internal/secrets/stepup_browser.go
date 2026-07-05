// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// BrowserOpener launches a URL in the user's browser. It is best-effort: the
// caller always prints the URL too, so a launch failure is not fatal.
type BrowserOpener func(rawURL string) error

// RequestStepUpViaBrowser drives the operation-bound WebAuthn step-up through
// the IdP-hosted ceremony page and returns the resulting operation-bound access
// token (amr:["webauthn"], vault_op). It is the human counterpart to
// requestExportStepUp's software-authenticator path.
//
// The CLI holds the owner bearer and drives /begin; the browser page (served
// same-origin by the IdP, so the assertion validates against the RP ID) runs
// navigator.credentials.get() against the owner's passkey and POSTs the
// assertion to /complete; the IdP stashes the issued token and the CLI collects
// it here by polling /token with the same owner bearer.
//
// operation is "promote" or "export". measurementDigestHex is the pending
// profile's profile_binding_digest for promote (empty for export). policyVersion
// is the key's current policy version. Both are baked into the vault_op binding
// server-side, so the token authorises this exact operation and nothing else.
func RequestStepUpViaBrowser(ctx context.Context, issuer, bearer, operation, handle, measurementDigestHex string, policyVersion uint32, open BrowserOpener, out io.Writer) (string, error) {
	issuer = strings.TrimRight(issuer, "/")

	// 1. Begin: authenticate with the owner bearer; the IdP fixes the nonce+exp,
	//    computes the vault_op binding, and returns it as the WebAuthn challenge.
	beginBody, _ := json.Marshal(map[string]interface{}{
		"operation":          operation,
		"handle":             handle,
		"measurement_digest": measurementDigestHex,
		"policy_version":     policyVersion,
		"ttl_seconds":        240,
	})
	optionsJSON, err := postBearer(ctx, issuer+"/fido2/vault-approval/begin", bearer, beginBody)
	if err != nil {
		return "", fmt.Errorf("step-up begin: %w", err)
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil || opts.PublicKey.Challenge == "" {
		return "", fmt.Errorf("step-up begin: no challenge in options")
	}
	vaultOp := opts.PublicKey.Challenge

	// 2. Hand the WebAuthn options to the browser page via the URL fragment (never
	//    sent to a server). A short summary drives the confirm screen.
	frag := struct {
		Options json.RawMessage   `json:"options"`
		Summary map[string]string `json:"summary"`
	}{
		Options: json.RawMessage(optionsJSON),
		Summary: map[string]string{"operation": operation, "handle": handle, "measurement": measurementDigestHex},
	}
	fragJSON, _ := json.Marshal(frag)
	pageURL := issuer + "/fido2/vault-approval#" + base64.RawURLEncoding.EncodeToString(fragJSON)

	fmt.Fprintf(out, "\nThis %s needs a hardware-backed approval. Open this URL and confirm with your passkey:\n\n  %s\n\n", operation, pageURL)
	if open != nil {
		if err := open(pageURL); err == nil {
			fmt.Fprintln(out, "(opened in your browser; if nothing appeared, use the URL above)")
		}
	}
	fmt.Fprintln(out, "Waiting for approval…")

	// 3. Poll for the token the browser's /complete stashed. Owner-scoped and
	//    single-use server-side. Bounded by the token's freshness window.
	tokenURL := issuer + "/fido2/vault-approval/token?challenge=" + url.QueryEscape(vaultOp)
	deadline := time.Now().Add(4 * time.Minute)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("step-up timed out waiting for browser approval")
		}
		tok, pending, err := getStepUpToken(ctx, tokenURL, bearer)
		if err != nil {
			return "", err
		}
		if !pending {
			fmt.Fprintln(out, "Approved.")
			return tok, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// getStepUpToken polls the IdP token endpoint. It returns (token, false, nil)
// on success, ("", true, nil) while the ceremony is still pending (HTTP 202),
// and a hard error on anything else.
func getStepUpToken(ctx context.Context, u, bearer string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusAccepted {
		return "", true, nil
	}
	if resp.StatusCode >= 400 {
		return "", false, fmt.Errorf("step-up poll -> %d: %s", resp.StatusCode, data)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", false, fmt.Errorf("step-up poll: no access_token in response")
	}
	return out.AccessToken, false, nil
}

// OpenBrowser launches rawURL in the user's default browser, best-effort. Under
// WSL it prefers wslview (opens the Windows browser, which holds the passkey /
// can bridge to the phone) before falling back to xdg-open.
func OpenBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	case "darwin":
		return exec.Command("open", rawURL).Start()
	default: // linux, incl. WSL
		if path, err := exec.LookPath("wslview"); err == nil {
			return exec.Command(path, rawURL).Start()
		}
		return exec.Command("xdg-open", rawURL).Start()
	}
}
