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

// RequestStepUpViaBrowser drives the operation-bound WebAuthn step-up and
// returns the resulting operation-bound access token (amr:["webauthn"],
// vault_op). It is the human counterpart to requestExportStepUp's
// software-authenticator path.
//
// The CLI holds the owner bearer and drives /begin, which does two things: it
// PUSHES the owner's Privasys Wallet (the usual approver — its credential is
// held in-app, so no browser can reach it) and it returns the WebAuthn options
// for the IdP-hosted ceremony page (the fallback for a genuine system passkey).
// Whichever surface the owner uses POSTs the assertion to /complete; the IdP
// stashes the issued token and the CLI collects it here by polling /token with
// the same owner bearer. The name is historical — the wallet is the primary
// path.
//
// operation is "promote", "export", or "policy-update" (idp-v0.3.32+; a
// key-policy update — e.g. arming the acceptable-TCB set — with an honest
// approval card). measurementDigestHex is the pending profile's
// profile_binding_digest for promote (empty for export/policy-update). policyVersion
// is the key's current policy version. Both are baked into the vault_op binding
// server-side, so the token authorises this exact operation and nothing else.
// approvalContext is advisory display context (app name, version, source,
// key type) the initiator attaches so the approver's wallet/browser can show a
// human-meaningful operation instead of a bare hex digest. It is NOT bound into
// the vault_op binding — the vault enforces only the operation tuple — so it is
// a convenience hint, never the security decision.
type approvalContext map[string]string

func RequestStepUpViaBrowser(ctx context.Context, issuer, bearer, operation, handle, measurementDigestHex string, policyVersion uint32, actx approvalContext, open BrowserOpener, out io.Writer) (string, error) {
	issuer = strings.TrimRight(issuer, "/")

	// 1. Begin: authenticate with the owner bearer; the IdP fixes the nonce+exp,
	//    computes the vault_op binding, and returns it as the WebAuthn challenge.
	beginBody, _ := json.Marshal(map[string]interface{}{
		"operation":          operation,
		"handle":             handle,
		"measurement_digest": measurementDigestHex,
		"policy_version":     policyVersion,
		// 300 is the IdP's cap; a LARGER value silently collapses to 120
		// (vault_approval.go), shortening the window instead of extending it.
		"ttl_seconds": 300,
		"context":            actx,
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
	summary := map[string]string{"operation": operation, "handle": handle, "measurement": measurementDigestHex}
	for k, v := range actx {
		if v != "" {
			summary[k] = v
		}
	}
	frag := struct {
		Options json.RawMessage   `json:"options"`
		Summary map[string]string `json:"summary"`
	}{
		Options: json.RawMessage(optionsJSON),
		Summary: summary,
	}
	fragJSON, _ := json.Marshal(frag)
	pageURL := issuer + "/fido2/vault-approval#" + base64.RawURLEncoding.EncodeToString(fragJSON)

	// The wallet is the PRIMARY approver: /begin already pushed it, and a
	// Privasys Wallet credential is in-app, not an iOS/Android system
	// passkey — a desktop browser can never reach it. The ceremony page
	// below is the fallback for owners whose credential really is a system
	// passkey (a platform authenticator or a security key).
	fmt.Fprintf(out, "\nThis %s needs a hardware-backed approval.\n\n"+
		"  ➊ In the Privasys Wallet: tap the \"Vault approval\" push, or open\n"+
		"     Settings → Vault approvals and confirm the request.\n\n"+
		"  ➋ Or, if your passkey is a system passkey (platform authenticator or\n"+
		"     security key), approve it in a browser:\n\n     %s\n\n", operation, pageURL)
	if open != nil {
		if err := open(pageURL); err == nil {
			fmt.Fprintln(out, "(the browser page was opened for ➋; wallet users can ignore it)")
		}
	}
	fmt.Fprintln(out, "Waiting for approval…")

	// 3. Poll for the token that /complete stashed (from the wallet or the
	//    browser page — both land in the same place). Owner-scoped and
	//    single-use server-side.
	tokenURL := issuer + "/fido2/vault-approval/token?challenge=" + url.QueryEscape(vaultOp)
	// Match the pending's own lifetime (the IdP caps ttl_seconds at 300):
	// polling longer just waits on an entry the server has already dropped.
	deadline := time.Now().Add(5*time.Minute + 20*time.Second)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("step-up timed out waiting for approval (wallet or browser)")
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
