// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/ratls"
	"github.com/Privasys/cli/internal/secrets"
)

var (
	errNoVersions   = errors.New("app has no versions; create one first")
	errPickEnclave  = errors.New("multiple or no compatible enclaves; pass 'enclave' explicitly")
	errPickLocation = errors.New("multiple or no locations available; pass 'location' explicitly")
)

// registerTools wires the full CLI surface as MCP tools.
func (s *Server) registerTools() {
	s.tools = []tool{
		{
			Name:        "whoami",
			Description: "Show the authenticated identity (subject, roles, audience).",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return auth.Claims(d.Token)
			},
		},
		{
			Name:        "auth_status",
			Description: "Report whether the user is signed in (and the identity if so). Use this first when onboarding.",
			noAuth:      true,
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				if !d.Authed {
					return map[string]interface{}{"authenticated": false}, nil
				}
				claims, _ := auth.Claims(d.Token)
				return map[string]interface{}{"authenticated": true, "identity": claims}, nil
			},
		},
		{
			Name:        "auth_begin",
			Description: "Start sign-in (OAuth device grant). Returns a verification URL + short user code to show the human; they approve EXTERNALLY in the Privasys Wallet or with a passkey. Then call auth_poll until authenticated. Never asks for or handles credentials.",
			noAuth:      true,
			Schema: obj(map[string]interface{}{
				"agent": strProp("name of the agent requesting access, shown to the user (unverified)"),
			}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				dr, verifier, err := auth.BeginDevice(ctx, d.Issuer, auth.DefaultScope, argStr(args, "agent"))
				if err != nil {
					return nil, err
				}
				// The device_code + PKCE verifier stay in a 0600 file, never in
				// the tool result (they would otherwise reach the model).
				_ = auth.SavePending(auth.PendingDevice{
					Issuer: d.Issuer, DeviceCode: dr.DeviceCode, Verifier: verifier,
					UserCode: dr.UserCode, Interval: dr.Interval,
					ExpiresAt: time.Now().Add(time.Duration(dr.ExpiresIn) * time.Second),
				})
				return map[string]interface{}{
					"verification_uri":          dr.VerificationURI,
					"verification_uri_complete": dr.VerificationURIComplete,
					"user_code":                 dr.UserCode,
					"expires_in":                dr.ExpiresIn,
					"interval":                  dr.Interval,
					"next":                      "Show the user verification_uri + user_code (or verification_uri_complete). After they approve, call auth_poll repeatedly until status is authenticated.",
				}, nil
			},
		},
		{
			Name:        "auth_poll",
			Description: "Poll the pending sign-in once. Returns {status:authenticated, identity} when the user has approved, or {status:pending}. Call repeatedly (respecting the interval) until authenticated.",
			noAuth:      true,
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				pend, err := auth.LoadPending()
				if err != nil {
					return nil, err
				}
				tr, _, err := auth.PollOnce(ctx, pend.Issuer, pend.DeviceCode, pend.Verifier)
				if err != nil {
					return nil, err
				}
				if tr == nil {
					return map[string]interface{}{"status": "pending"}, nil
				}
				if err := auth.SaveUserCredential(pend.Issuer, tr); err != nil {
					return nil, err
				}
				auth.RemovePending()
				claims, _ := auth.Claims(tr.AccessToken)
				return map[string]interface{}{"status": "authenticated", "identity": claims}, nil
			},
		},
		{
			Name:        "billing_portal",
			Description: "Get the Stripe billing portal URL for the user to manage their payment method and subscription EXTERNALLY. Surface the URL; never handle card data. Poll billing_status for the result.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				url, ok, err := d.Client.BillingPortal(ctx)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"url": url, "available": ok}, nil
			},
		},
		{
			Name:        "billing_subscribe",
			Description: "Get a Stripe Checkout URL for the user to start the platform membership EXTERNALLY. 'kind' is membership (default) or credits. Surface the URL; poll billing_status until active. No card data touches the agent.",
			Schema: obj(map[string]interface{}{
				"kind": strProp("membership (default) or credits"),
			}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				kind := argStr(args, "kind")
				if kind == "" {
					kind = "membership"
				}
				url, ok, err := d.Client.Checkout(ctx, kind)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"checkout_url": url, "available": ok}, nil
			},
		},
		{
			Name:        "secrets_create",
			Description: "Create a user-owned secret (key) in the vault constellation for the signed-in user. Generates RANDOM material — the agent never sees or handles the secret bytes; the owner can export it later. The key is Shamir-split across the vaults; the platform never holds it.",
			Schema: obj(map[string]interface{}{
				"name":         strProp("secret name (created under your own namespace)"),
				"random_bytes": intProp("bytes of randomness to generate (default 32)"),
				"exportable":   boolProp("allow the owner to export it later (default true)"),
			}, "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				claims, err := auth.Claims(d.Token)
				if err != nil {
					return nil, err
				}
				sub, _ := claims["sub"].(string)
				if sub == "" {
					return nil, errors.New("could not determine your subject from the session")
				}
				n := argInt(args, "random_bytes")
				if n <= 0 {
					n = 32
				}
				material := make([]byte, n)
				if _, err := rand.Read(material); err != nil {
					return nil, err
				}
				exportable := true
				if v, ok := args["exportable"].(bool); ok {
					exportable = v
				}
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				endpoints, mrenclave, attServer := mcpConstellation(ctx, d)
				return secrets.Create(ctx, secrets.CreateParams{
					Issuer: d.Issuer, Bearer: d.Token, Sub: sub,
					Handle: "users/" + sub + "/" + name, Secret: material, Exportable: exportable,
					Endpoints: endpoints, Threshold: 2,
					MRENCLAVE: mrenclave, AttServer: attServer, AttToken: attTok,
				})
			},
		},
		{
			Name: "secrets_export",
			Description: "Export a secret the signed-in user owns to a LOCAL FILE. DANGEROUS: writes raw key material to disk. " +
				"The key is NEVER returned to you — only the file path and a fingerprint. Confirm with the human first. " +
				"Requires a fresh WebAuthn step-up the owner approves in their wallet; you cannot approve it.",
			Schema: obj(map[string]interface{}{
				"name": strProp("the secret's name (under your own namespace)"),
				"out":  strProp("local file path to write the raw key to (required)"),
			}, "name", "out"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				out, err := requireStr(args, "out")
				if err != nil {
					return nil, err
				}
				claims, err := auth.Claims(d.Token)
				if err != nil {
					return nil, err
				}
				sub, _ := claims["sub"].(string)
				if sub == "" {
					return nil, errors.New("could not determine your subject from the session")
				}
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				endpoints, mrenclave, attServer := mcpConstellation(ctx, d)
				material, res, err := secrets.Export(ctx, secrets.ExportParams{
					Issuer: d.Issuer, Bearer: d.Token, Sub: sub,
					Handle:    "users/" + sub + "/" + name,
					Endpoints: endpoints, Threshold: 2,
					MRENCLAVE: mrenclave, AttServer: attServer, AttToken: attTok,
					RequireStepUp: true,
					// The agent cannot approve WebAuthn step-up; the human does it in
					// their wallet. Surfaced as a clear instruction until the wallet
					// Vault-approvals relay lands.
					Assert: func(context.Context, []byte) ([]byte, error) {
						return nil, errors.New("export needs WebAuthn step-up: the owner must approve it in the Privasys Wallet under Vault approvals")
					},
				})
				if err != nil {
					return nil, err
				}
				werr := os.WriteFile(out, material, 0o600)
				for i := range material {
					material[i] = 0
				}
				if werr != nil {
					return nil, werr
				}
				// Return path + fingerprint only — never the material.
				return map[string]interface{}{
					"path": out, "fingerprint": res.Fingerprint,
					"handle": res.Handle, "vaults": res.Retrieved, "written": true,
				}, nil
			},
		},
		{
			Name:        "vault_create",
			Description: "Create a user vault (a key container) billed to the signed-in account. Keys + secrets live under it.",
			Schema:      obj(map[string]interface{}{"name": strProp("vault name")}, "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				return d.Client.CreateVault(ctx, name)
			},
		},
		{
			Name:        "vault_list",
			Description: "List the caller's vaults.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.ListVaults(ctx)
			},
		},
		{
			Name:        "vault_key_create",
			Description: "Create a key in one of your vaults. Generates RANDOM material — you never see or handle the bytes; the platform never holds it (Shamir-split across the constellation). The owner can export it later.",
			Schema: obj(map[string]interface{}{
				"vault_id":   strProp("the vault id"),
				"name":       strProp("key name (under the vault)"),
				"exportable": boolProp("allow the owner to export it later (default true)"),
			}, "vault_id", "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				claims, err := auth.Claims(d.Token)
				if err != nil {
					return nil, err
				}
				sub, _ := claims["sub"].(string)
				exportable := true
				if v, ok := args["exportable"].(bool); ok {
					exportable = v
				}
				material := make([]byte, 32)
				if _, err := rand.Read(material); err != nil {
					return nil, err
				}
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				return secrets.CreateInVault(ctx, secrets.VaultCreateParams{
					Sub: sub, Secret: material, Exportable: exportable, AttToken: attTok,
					MintGrant: func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
						r, err := d.Client.MintVaultKeyGrant(ctx, vaultID, name, "", cnf, exportable, "", "")
						if err != nil {
							return "", secrets.VaultAddressing{}, err
						}
						handle, _ := r.Key["handle"].(string)
						return r.Grant, secrets.VaultAddressing{
							Handle:    handle,
							Endpoints: r.Constellation.Endpoints,
							MRENCLAVE: r.Constellation.MRENCLAVE,
							AttServer: r.Constellation.AttestationServer,
							Threshold: r.Constellation.Threshold,
						}, nil
					},
				})
			},
		},
		{
			Name: "registry_status",
			Description: "Report whether an app has a private-registry pull credential configured. Read-only. " +
				"NOTE: registering the credential is a HUMAN step — ask the user to run `privasys registry add <app> --token …`; never handle their registry token yourself.",
			Schema: obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.GetRegistrySecret(ctx, appID)
			},
		},
		{
			Name: "apps_export_key",
			Description: "Export an app's data encryption key (owned by the signed-in app owner) to a LOCAL FILE. DANGEROUS: writes raw key material to disk. " +
				"The key is NEVER returned to you — only the file path and a fingerprint. Confirm with the human first. " +
				"Depending on policy this may require a WebAuthn step-up the owner approves in their wallet; you cannot approve it.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"out":    strProp("local file path to write the raw key to (required)"),
			}, "app_id", "out"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				out, err := requireStr(args, "out")
				if err != nil {
					return nil, err
				}
				claims, err := auth.Claims(d.Token)
				if err != nil {
					return nil, err
				}
				sub, _ := claims["sub"].(string)
				target, err := d.Client.GetVaultExportTarget(ctx, appID)
				if err != nil {
					return nil, err
				}
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				material, res, err := secrets.Export(ctx, secrets.ExportParams{
					Issuer: d.Issuer, Bearer: d.Token, Sub: sub, Handle: target.Handle,
					Endpoints: target.Endpoints, Threshold: target.Threshold,
					MRENCLAVE: target.MRENCLAVE, AttServer: target.AttestationServer, AttToken: attTok,
					RequireStepUp:  target.RequireStepUp,
					GenerationSize: secrets.AppDEKGenerationSize,
					Assert: func(context.Context, []byte) ([]byte, error) {
						return nil, errors.New("export needs WebAuthn step-up: the owner must approve it in the Privasys Wallet under Vault approvals")
					},
				})
				if err != nil {
					return nil, err
				}
				werr := os.WriteFile(out, material, 0o600)
				for i := range material {
					material[i] = 0
				}
				if werr != nil {
					return nil, werr
				}
				return map[string]interface{}{
					"path": out, "fingerprint": res.Fingerprint,
					"handle": res.Handle, "vaults": res.Retrieved, "written": true,
				}, nil
			},
		},
		{
			Name:        "apps_configure",
			Description: "Apply a confidential app's owner-only setup (its image-declared `configure` section, or a legacy role:config tool), which lifts the configure-then-freeze gate so the app starts serving. The config fields come from the app's manifest (see apps_api). 'config' is the JSON config object. Do NOT pass a secret the user asked you not to handle (e.g. an API key) — surface those for the human to set.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"config": map[string]interface{}{"type": "object", "description": "config values per the configure section's input schema"},
			}, "app_id", "config"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				config, _ := args["config"].(map[string]interface{})
				if config == nil {
					config = map[string]interface{}{}
				}
				schema, err := d.Client.Schema(ctx, appID)
				if err != nil {
					return nil, err
				}
				name := configRPCName(schema)
				if name == "" {
					return nil, errors.New("app declares no configuration")
				}
				res, err := d.Client.Rpc(ctx, appID, name, config)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"configured": true, "tool": name, "result": res}, nil
			},
		},
		{
			Name:        "apps_action",
			Description: "Run a confidential app's role:action operation by name (e.g. load_model) via the owner-authed control plane. 'args' is the JSON input (per the action tool's schema; see apps_api). Returns the result; for a long-running action, poll the app's status tool with apps_call to follow progress.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"name":   strProp("the action tool name"),
				"args":   map[string]interface{}{"type": "object", "description": "the action inputs"},
			}, "app_id", "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				body, _ := args["args"].(map[string]interface{})
				if body == nil {
					body = map[string]interface{}{}
				}
				return d.Client.Rpc(ctx, appID, name, body)
			},
		},
		{
			Name:        "vault_key_sign",
			Description: "Sign a message with a vault signing key. The private key never leaves the constellation — it is signed in-enclave over RA-TLS. Returns the signature (base64) and algorithm. Set prehashed:true when 'message' is a pre-computed SHA-256 digest as 64 hex chars — it is signed raw (CKM_ECDSA, no re-hash), what TLS stacks and code signers need.",
			Schema: obj(map[string]interface{}{
				"vault_id":  strProp("the vault id"),
				"name":      strProp("the key name"),
				"message":   strProp("the message to sign (UTF-8 text), or with prehashed: the 32-byte SHA-256 digest as 64 hex chars"),
				"version":   intProp("key version (0 = current primary)"),
				"prehashed": boolProp("message is a SHA-256 digest (64 hex chars); sign it raw, no re-hash"),
			}, "vault_id", "name", "message"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				message, err := requireStr(args, "message")
				if err != nil {
					return nil, err
				}
				p, err := vaultKeyAddr(ctx, d, vaultID, name, argInt(args, "version"))
				if err != nil {
					return nil, err
				}
				var res *secrets.SignResult
				if pre, _ := args["prehashed"].(bool); pre {
					digest, derr := secrets.DigestBytes([]byte(message))
					if derr != nil {
						return nil, derr
					}
					res, err = secrets.SignPrehashInVault(ctx, p, digest)
				} else {
					res, err = secrets.SignInVault(ctx, p, []byte(message))
				}
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"alg": res.Alg, "vault": res.Vault, "signature_b64": base64.StdEncoding.EncodeToString(res.Signature)}, nil
			},
		},
		{
			Name:        "vault_key_public",
			Description: "Get a vault signing key's public half (key type + the public key, base64). The private half never leaves the constellation.",
			Schema: obj(map[string]interface{}{
				"vault_id": strProp("the vault id"),
				"name":     strProp("the key name"),
				"version":  intProp("key version (0 = current primary)"),
			}, "vault_id", "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				p, err := vaultKeyAddr(ctx, d, vaultID, name, argInt(args, "version"))
				if err != nil {
					return nil, err
				}
				res, err := secrets.GetPublicKeyInVault(ctx, p)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"key_type": res.KeyType, "vault": res.Vault, "public_key_b64": base64.StdEncoding.EncodeToString(res.PublicKey)}, nil
			},
		},
		{
			Name:        "vault_rm",
			Description: "Delete a vault (key container) by id.",
			Schema:      obj(map[string]interface{}{"vault_id": strProp("the vault id")}, "vault_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				if err := d.Client.DeleteVault(ctx, vaultID); err != nil {
					return nil, err
				}
				return map[string]interface{}{"deleted": true, "vault_id": vaultID}, nil
			},
		},
		{
			Name:        "vault_key_list",
			Description: "List the keys in a vault (name, type, version).",
			Schema:      obj(map[string]interface{}{"vault_id": strProp("the vault id")}, "vault_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				return d.Client.ListVaultKeys(ctx, vaultID)
			},
		},
		{
			Name:        "vault_key_wrap",
			Description: "Encrypt data under a vault AES-256-GCM key (in-enclave; the key never leaves the constellation). 'plaintext' is the UTF-8 data to encrypt. Returns ciphertext + IV (base64) to pass to vault_key_unwrap.",
			Schema: obj(map[string]interface{}{
				"vault_id":  strProp("the vault id"),
				"name":      strProp("the AES key name"),
				"plaintext": strProp("the data to encrypt (UTF-8 text)"),
			}, "vault_id", "name", "plaintext"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				plaintext, err := requireStr(args, "plaintext")
				if err != nil {
					return nil, err
				}
				p, err := vaultKeyAddr(ctx, d, vaultID, name, 0)
				if err != nil {
					return nil, err
				}
				ct, iv, vaultEp, err := secrets.WrapInVault(ctx, p, []byte(plaintext), nil, nil)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{
					"ciphertext_b64": base64.StdEncoding.EncodeToString(ct),
					"iv_b64":         base64.StdEncoding.EncodeToString(iv),
					"vault":          vaultEp,
				}, nil
			},
		},
		{
			Name:        "vault_key_unwrap",
			Description: "Decrypt data under a vault AES-256-GCM key (in-enclave). Pass the ciphertext + IV (base64) from vault_key_wrap. Returns the plaintext (base64). NOTE: the decrypted data is returned to you — only do this when the user wants the plaintext.",
			Schema: obj(map[string]interface{}{
				"vault_id":       strProp("the vault id"),
				"name":           strProp("the AES key name"),
				"ciphertext_b64": strProp("base64 ciphertext from vault_key_wrap"),
				"iv_b64":         strProp("base64 IV from vault_key_wrap"),
				"version":        intProp("key version that wrapped the data (0 = current primary)"),
			}, "vault_id", "name", "ciphertext_b64", "iv_b64"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				ctB64, err := requireStr(args, "ciphertext_b64")
				if err != nil {
					return nil, err
				}
				ivB64, err := requireStr(args, "iv_b64")
				if err != nil {
					return nil, err
				}
				ct, err := base64.StdEncoding.DecodeString(ctB64)
				if err != nil {
					return nil, fmt.Errorf("ciphertext_b64: %w", err)
				}
				iv, err := base64.StdEncoding.DecodeString(ivB64)
				if err != nil {
					return nil, fmt.Errorf("iv_b64: %w", err)
				}
				p, err := vaultKeyAddr(ctx, d, vaultID, name, argInt(args, "version"))
				if err != nil {
					return nil, err
				}
				pt, vaultEp, err := secrets.UnwrapInVault(ctx, p, ct, iv, nil)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"plaintext_b64": base64.StdEncoding.EncodeToString(pt), "vault": vaultEp}, nil
			},
		},
		{
			Name:        "vault_key_rotate",
			Description: "Rotate a key: create a new primary version with fresh material (generated in-enclave / client-side; you never see it). Old versions are retained so data signed/wrapped under them still verifies/unwraps.",
			Schema: obj(map[string]interface{}{
				"vault_id": strProp("the vault id"),
				"name":     strProp("the key name"),
			}, "vault_id", "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				claims, err := auth.Claims(d.Token)
				if err != nil {
					return nil, err
				}
				sub, _ := claims["sub"].(string)
				keyType, err := primaryVaultKeyType(ctx, d, vaultID, name)
				if err != nil {
					return nil, err
				}
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				mint := func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
					r, err := d.Client.RotateVaultKeyGrant(ctx, vaultID, name, cnf)
					if err != nil {
						return "", secrets.VaultAddressing{}, err
					}
					handle, _ := r.Key["handle"].(string)
					return r.Grant, secrets.VaultAddressing{
						Handle: handle, Endpoints: r.Constellation.Endpoints, MRENCLAVE: r.Constellation.MRENCLAVE,
						AttServer: r.Constellation.AttestationServer, Threshold: r.Constellation.Threshold,
					}, nil
				}
				params := secrets.VaultCreateParams{Sub: sub, AttToken: attTok, MintGrant: mint}
				switch keyType {
				case "P256SigningKey":
					return secrets.CreateSigningKeyInVault(ctx, params)
				case "Aes256GcmKey":
					return secrets.CreateAesKeyInVault(ctx, params)
				default:
					material := make([]byte, 32)
					if _, err := rand.Read(material); err != nil {
						return nil, err
					}
					params.Secret, params.Exportable = material, true
					return secrets.CreateInVault(ctx, params)
				}
			},
		},
		{
			Name:        "vault_key_rm",
			Description: "Delete a key. DANGEROUS by default it cryptographically DESTROYS the key material on the constellation (irreversible) then removes the catalogue entry. Set catalogue_only:true to forget the key in your listing without destroying the material. Confirm with the human first.",
			Schema: obj(map[string]interface{}{
				"vault_id":       strProp("the vault id"),
				"name":           strProp("the key name"),
				"catalogue_only": boolProp("remove the catalogue entry only; leave the material on the vaults"),
			}, "vault_id", "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				catalogueOnly, _ := args["catalogue_only"].(bool)
				deletedOn := []string{}
				if !catalogueOnly {
					p, perr := vaultKeyAddr(ctx, d, vaultID, name, 0)
					if perr != nil {
						return nil, perr
					}
					if deletedOn, err = secrets.DestroyKeyInVault(ctx, p); err != nil {
						return nil, fmt.Errorf("destroy key material: %w", err)
					}
				}
				if err := d.Client.DeleteVaultKey(ctx, vaultID, name); err != nil {
					return nil, err
				}
				return map[string]interface{}{"deleted": true, "destroyed_on": deletedOn}, nil
			},
		},
		{
			Name:        "vault_key_audit",
			Description: "Read a key's tamper-evident audit log (every operation, the caller, allowed/denied), read directly from the holder vault.",
			Schema: obj(map[string]interface{}{
				"vault_id": strProp("the vault id"),
				"name":     strProp("the key name"),
				"limit":    intProp("max entries (default 50)"),
			}, "vault_id", "name"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				vaultID, err := requireStr(args, "vault_id")
				if err != nil {
					return nil, err
				}
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				limit := argInt(args, "limit")
				if limit <= 0 {
					limit = 50
				}
				p, err := vaultKeyAddr(ctx, d, vaultID, name, 0)
				if err != nil {
					return nil, err
				}
				entries, vaultEp, err := secrets.ReadAuditInVault(ctx, p, limit)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"entries": entries, "vault": vaultEp}, nil
			},
		},
		{
			Name:        "apps_owners_list",
			Description: "List who can access an app (its owners).",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.ListAppOwners(ctx, appID)
			},
		},
		{
			Name:        "apps_owners_add",
			Description: "Grant a member (by their subject) access to an app.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"sub":    strProp("the member's subject (privasys.id sub)"),
				"email":  strProp("member email (optional)"),
				"name":   strProp("member name (optional)"),
			}, "app_id", "sub"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				sub, err := requireStr(args, "sub")
				if err != nil {
					return nil, err
				}
				owner := map[string]interface{}{"sub": sub}
				if e := argStr(args, "email"); e != "" {
					owner["email"] = e
				}
				if n := argStr(args, "name"); n != "" {
					owner["name"] = n
				}
				return d.Client.AddAppOwner(ctx, appID, owner)
			},
		},
		{
			Name:        "apps_owners_remove",
			Description: "Remove a member's access to an app.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"sub":    strProp("the member's subject to remove"),
			}, "app_id", "sub"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				appID, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				sub, err := requireStr(args, "sub")
				if err != nil {
					return nil, err
				}
				return d.Client.RemoveAppOwner(ctx, appID, sub)
			},
		},
		{
			Name:        "apps_list",
			Description: "List the caller's apps.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.ListApps(ctx)
			},
		},
		{
			Name:        "apps_describe",
			Description: "Show an app's details (version, source, enclave, status).",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.GetApp(ctx, id)
			},
		},
		{
			Name:        "apps_create",
			Description: "Create a new app.",
			Schema: obj(map[string]interface{}{
				"name":         strProp("app name (DNS-safe)"),
				"source_type":  strProp("upload|github|package|cloud_image"),
				"app_type":     strProp("wasm|container"),
				"commit_url":   strProp("GitHub commit URL (github source)"),
				"image":        strProp("container image ref (package source)"),
				"display_name": strProp("human-friendly name"),
				"description":  strProp("description"),
				"storage":      boolProp("request encrypted, owner-controlled storage (for apps that hold user data)"),
				"size":         strProp("container VM size slug: micro|small|medium|large|xlarge (default micro; container apps only, fixed at creation)"),
			}, "name", "source_type"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				name, err := requireStr(args, "name")
				if err != nil {
					return nil, err
				}
				src, err := requireStr(args, "source_type")
				if err != nil {
					return nil, err
				}
				body := map[string]interface{}{"name": name, "source_type": src}
				for _, k := range []string{"app_type", "commit_url", "display_name", "description"} {
					if v := argStr(args, k); v != "" {
						body[mapKey(k)] = v
					}
				}
				if v := argStr(args, "image"); v != "" {
					body["container_image"] = v
				}
				if b, _ := args["storage"].(bool); b {
					body["container_storage"] = true
				}
				if v := argStr(args, "size"); v != "" {
					body["instance_size"] = v // server validates the slug
				}
				// container_port is platform-allocated (app listens on $PORT).
				return d.Client.CreateApp(ctx, body)
			},
		},
		{
			Name:        "apps_store_listing",
			Description: "Set an app's App Store listing. A description and category are REQUIRED before the app can be deployed or published, so call this after apps_create and before apps_deploy.",
			Schema: obj(map[string]interface{}{
				"app_id":      strProp("the app id"),
				"description": strProp("what the app does (required before deploy)"),
				"category":    strProp("store category, e.g. 'Developer Tools' (required before deploy)"),
				"tagline":     strProp("short one-line tagline"),
				"keywords":    strProp("comma-separated keywords"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				fields := map[string]interface{}{}
				for arg, key := range map[string]string{
					"description": "store_description", "category": "store_category",
					"tagline": "store_tagline", "keywords": "store_keywords",
				} {
					if v := argStr(args, arg); v != "" {
						fields[key] = v
					}
				}
				if len(fields) == 0 {
					return nil, errors.New("nothing to set; provide at least description and category")
				}
				return d.Client.UpdateStoreListing(ctx, id, fields)
			},
		},
		{
			Name:        "apps_versions",
			Description: "List an app's versions.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.ListVersions(ctx, id)
			},
		},
		{
			Name:        "apps_deploy",
			Description: "Deploy a version of an app (defaults to the latest version and, when there is only one, the sole location). Adopters pick a location, not an enclave.",
			Schema: obj(map[string]interface{}{
				"app_id":   strProp("the app id"),
				"version":  strProp("version id (default: latest)"),
				"location": strProp("deploy location code, e.g. europe-west9 (default: the only one available)"),
				"enclave":  strProp("enclave id (admin override; adopters use location)"),
				"size":     strProp("container VM size for this deployment: micro|small|medium|large|xlarge (default: the app's size; redeploy with a new size to resize)"),
				"tenancy":  strProp("mutualised (default, shared CVM) or dedicated (a whole confidential VM, Medium/Large only)"),
				"instance": strProp("deploy onto a dedicated instance id you own (multi-app; overrides location/tenancy)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				versionID := argStr(args, "version")
				if versionID == "" {
					vs, err := d.Client.ListVersions(ctx, id)
					if err != nil {
						return nil, err
					}
					if len(vs) == 0 {
						return nil, errNoVersions
					}
					versionID, _ = vs[len(vs)-1]["id"].(string)
				}
				// Placement: --instance (an owned dedicated instance) wins,
				// then an explicit enclave (admin), then the location — use the
				// given one, or auto-pick the sole location.
				enclaveID := argStr(args, "enclave")
				location := argStr(args, "location")
				instanceID := argStr(args, "instance")
				if instanceID == "" && enclaveID == "" && location == "" {
					locs, err := d.Client.DeployLocations(ctx, id)
					if err != nil {
						return nil, err
					}
					if len(locs) != 1 {
						return nil, errPickLocation
					}
					location, _ = locs[0]["code"].(string)
				}
				return d.Client.DeployVersion(ctx, id, versionID, enclaveID, location, argStr(args, "size"), argStr(args, "tenancy"), instanceID)
			},
		},
		{
			Name:        "apps_deployments",
			Description: "List an app's deployments and their runtime status.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.ListDeployments(ctx, id)
			},
		},
		{
			Name:        "apps_api",
			Description: "List an app's exported functions (schema).",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.Schema(ctx, id)
			},
		},
		{
			Name:        "apps_mcp",
			Description: "Show an app's MCP tool manifest.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.MCP(ctx, id)
			},
		},
		{
			Name:        "apps_call",
			Description: "Call an app function directly over RA-TLS (verifies the enclave first; control plane is not in the data path). 'data' is the JSON request body.",
			Schema: obj(map[string]interface{}{
				"app_id":   strProp("the app id"),
				"function": strProp("the function name"),
				"data":     map[string]interface{}{"description": "JSON request body"},
				"attest":   map[string]interface{}{"type": "boolean", "description": "also verify the quote against the attestation server"},
			}, "app_id", "function"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				fn, err := requireStr(args, "function")
				if err != nil {
					return nil, err
				}
				app, err := d.Client.GetApp(ctx, id)
				if err != nil {
					return nil, err
				}
				host, err := d.Client.ActiveDeploymentHost(ctx, id)
				if err != nil {
					return nil, err
				}
				name, _ := app["name"].(string)
				aType, _ := app["app_type"].(string)
				if aType == "" {
					aType = "wasm"
				}
				var body []byte
				if args["data"] != nil {
					body, _ = json.Marshal(args["data"])
				}
				path := ""
				if aType == "container" {
					path = containerPath(app, fn)
				}
				attURL, attTok := "", ""
				if b, _ := args["attest"].(bool); b {
					attURL = "https://as.privasys.org/verify"
					attTok, _ = auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				}
				var buf bytes.Buffer
				status, err := ratls.Call(ctx, ratls.CallParams{
					Host: host, ServerName: host, AppName: name, AppType: aType,
					Function: fn, Path: path, Body: body, AppToken: d.Token,
					Challenge: ratls.NewNonce(), AttServerURL: attURL, AttServerTok: attTok,
				}, &buf)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"status": status, "body": buf.String()}, nil
			},
		},
		{
			Name:        "apps_builds",
			Description: "List an app's build jobs.",
			Schema:      obj(map[string]interface{}{"app_id": strProp("the app id")}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				return d.Client.ListBuilds(ctx, id)
			},
		},
		{
			Name:        "apps_versions_stage",
			Description: "Stage the new measurement (enclave MRTD + image digest) for a vault-backed app version on the constellation. Owner-only. Staging grants no key access; it proposes the measurement a later promote authorises.",
			Schema: obj(map[string]interface{}{
				"app_id":  strProp("the app id"),
				"version": strProp("version id (default: latest)"),
				"enclave": strProp("enclave id (default: only compatible)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				vid, err := resolveLatestVersion(ctx, d, id, argStr(args, "version"))
				if err != nil {
					return nil, err
				}
				enc := argStr(args, "enclave")
				if enc == "" {
					encs, err := d.Client.CompatibleEnclaves(ctx, id)
					if err != nil {
						return nil, err
					}
					if len(encs) != 1 {
						return nil, errPickEnclave
					}
					enc, _ = encs[0]["id"].(string)
				}
				return d.Client.StageProfile(ctx, id, vid, enc)
			},
		},
		{
			Name:        "apps_versions_pending",
			Description: "List staged-but-unpromoted vault key profiles for a version, with the staged measurement and per-vault K-of-N progress. Owner-only.",
			Schema: obj(map[string]interface{}{
				"app_id":  strProp("the app id"),
				"version": strProp("version id (default: latest)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				vid, err := resolveLatestVersion(ctx, d, id, argStr(args, "version"))
				if err != nil {
					return nil, err
				}
				return d.Client.ListPending(ctx, id, vid)
			},
		},
		{
			Name:        "apps_versions_promote",
			Description: "Promote (approve) a staged measurement so the vault releases the data key to the new app/enclave version. Owner-only, and irreversible consent: surface the staged measurement (via apps_versions_pending) to a human and get explicit sign-off before calling this.",
			Schema: obj(map[string]interface{}{
				"app_id":     strProp("the app id"),
				"version":    strProp("version id (default: latest)"),
				"pending_id": intProp("pending profile id (default 0)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				vid, err := resolveLatestVersion(ctx, d, id, argStr(args, "version"))
				if err != nil {
					return nil, err
				}
				return d.Client.PromoteProfile(ctx, id, vid, argInt(args, "pending_id"))
			},
		},
		{
			Name:        "apps_versions_revoke",
			Description: "Drop a staged-but-unpromoted vault key profile. Owner-only.",
			Schema: obj(map[string]interface{}{
				"app_id":     strProp("the app id"),
				"version":    strProp("version id (default: latest)"),
				"pending_id": intProp("pending profile id (default 0)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				vid, err := resolveLatestVersion(ctx, d, id, argStr(args, "version"))
				if err != nil {
					return nil, err
				}
				return d.Client.RevokeProfile(ctx, id, vid, argInt(args, "pending_id"))
			},
		},
		{
			Name:        "apps_rotate_key",
			Description: "Rotate a vault-backed app's data encryption key (key hygiene, NOT an upgrade). The app keeps running and data is never re-encrypted: the platform provisions a new key generation, re-keys the running volume online, advances the key handle, and retires the old generation. Owner-only. Surface the resulting old→new key handles to a human; the app must be running on the target enclave.",
			Schema: obj(map[string]interface{}{
				"app_id":  strProp("the app id"),
				"version": strProp("the running version id (default: latest)"),
				"enclave": strProp("enclave the app runs on (default: only compatible)"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				vid, err := resolveLatestVersion(ctx, d, id, argStr(args, "version"))
				if err != nil {
					return nil, err
				}
				enc := argStr(args, "enclave")
				if enc == "" {
					encs, err := d.Client.CompatibleEnclaves(ctx, id)
					if err != nil {
						return nil, err
					}
					if len(encs) != 1 {
						return nil, errPickEnclave
					}
					enc, _ = encs[0]["id"].(string)
				}
				return d.Client.RotateKey(ctx, id, vid, enc)
			},
		},
		{
			Name:        "apps_versions_create",
			Description: "Ship a new version of an app. Pass the field matching the app's source: commit_url (github, GPG-signed commit), image (package, a container image ref), or channel (cloud_image). Optional version is a strictly-incrementing semver (vX.Y.Z); omitted auto-bumps the patch. Does not deploy.",
			Schema: obj(map[string]interface{}{
				"app_id":     strProp("the app id"),
				"commit_url": strProp("GitHub commit URL (github source)"),
				"image":      strProp("container image ref (package source)"),
				"channel":    strProp("cloud-image channel (cloud_image source)"),
				"version":    strProp("optional semver vX.Y.Z"),
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				body := map[string]string{}
				for _, k := range []string{"commit_url", "image", "channel", "version"} {
					if v := argStr(args, k); v != "" {
						body[k] = v
					}
				}
				return d.Client.CreateVersion(ctx, id, body)
			},
		},
		{
			Name:        "apps_cosign",
			Description: "Enable or disable separation-of-duties co-sign on promote for a vault-backed app: when on, a SECOND team approver must co-sign before an upgrade's data key is released. Owner-only.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"enable": boolProp("true to require co-sign, false to disable"),
			}, "app_id", "enable"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				enable, _ := args["enable"].(bool)
				return d.Client.SetVaultCosign(ctx, id, enable)
			},
		},
		{
			Name:        "apps_migrate_constellation",
			Description: "Migrate a vault-backed app's data key to a different vault constellation (advanced ops, e.g. region change). Owner-only. Surface the target to a human before running.",
			Schema: obj(map[string]interface{}{
				"app_id": strProp("the app id"),
				"target": strProp("the target constellation id"),
			}, "app_id", "target"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				id, err := requireStr(args, "app_id")
				if err != nil {
					return nil, err
				}
				target, err := requireStr(args, "target")
				if err != nil {
					return nil, err
				}
				return d.Client.MigrateConstellation(ctx, id, target)
			},
		},
		{
			Name:        "attest",
			Description: "Verify an app's enclave client-side: connect over RA-TLS, challenge it with a fresh nonce, and verify the quote against the attestation server. Does not trust the control plane.",
			Schema: obj(map[string]interface{}{
				"app_id":       strProp("the app id (used to resolve the enclave hostname)"),
				"host":         strProp("enclave gateway FQDN (optional; bypasses control-plane lookup)"),
				"no_challenge": map[string]interface{}{"type": "boolean", "description": "use deterministic mode instead of a fresh challenge"},
			}, "app_id"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				host := argStr(args, "host")
				if host == "" {
					id, err := requireStr(args, "app_id")
					if err != nil {
						return nil, err
					}
					host, err = d.Client.ActiveDeploymentHost(ctx, id)
					if err != nil {
						return nil, err
					}
				}
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				var nonce []byte
				if b, _ := args["no_challenge"].(bool); !b {
					nonce = ratls.NewNonce()
				}
				return ratls.Verify(ctx, ratls.Params{
					Host: host, Port: 443, ServerName: host,
					Challenge: nonce, AttServerURL: "https://as.privasys.org/verify", AttServerTok: attTok,
				})
			},
		},
		{
			Name:        "account_show",
			Description: "Show the current account and your role.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.GetAccount(ctx)
			},
		},
		{
			Name:        "team_list",
			Description: "List account members.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.ListMembers(ctx)
			},
		},
		{
			Name:        "team_add",
			Description: "Add an account member.",
			Schema: obj(map[string]interface{}{
				"sub":   strProp("the member's subject id"),
				"email": strProp("member email"),
				"name":  strProp("member name"),
				"role":  strProp("admin|billing|member"),
			}, "sub"),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				sub, err := requireStr(args, "sub")
				if err != nil {
					return nil, err
				}
				member := map[string]interface{}{"sub": sub}
				for _, k := range []string{"email", "name", "role"} {
					if v := argStr(args, k); v != "" {
						member[k] = v
					}
				}
				return d.Client.AddMember(ctx, member)
			},
		},
		{
			Name:        "billing_balance",
			Description: "Show the account's credit balance.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.BillingBalance(ctx)
			},
		},
		{
			Name:        "billing_usage",
			Description: "Show usage by resource. Optional 'since' (RFC3339).",
			Schema:      obj(map[string]interface{}{"since": strProp("RFC3339 start time")}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.BillingUsage(ctx, argStr(args, "since"))
			},
		},
		{
			Name:        "billing_ledger",
			Description: "Show the credit-ledger history. Optional 'limit'.",
			Schema:      obj(map[string]interface{}{"limit": intProp("max entries")}),
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.BillingLedger(ctx, argInt(args, "limit"))
			},
		},
		{
			Name:        "billing_status",
			Description: "Show the membership subscription state.",
			Handler: func(ctx context.Context, d Deps, args map[string]interface{}) (interface{}, error) {
				return d.Client.BillingSubscription(ctx)
			},
		},
	}
}

func mapKey(k string) string { return k }

// resolveLatestVersion returns ref if non-empty, else the id of the app's
// latest version.
func resolveLatestVersion(ctx context.Context, d Deps, appID, ref string) (string, error) {
	if ref != "" {
		return ref, nil
	}
	vs, err := d.Client.ListVersions(ctx, appID)
	if err != nil {
		return "", err
	}
	if len(vs) == 0 {
		return "", errNoVersions
	}
	id, _ := vs[len(vs)-1]["id"].(string)
	return id, nil
}

// containerPath maps a function name to a container endpoint via the app's
// privasys.json tool manifest, falling back to /<function>.
// mcpConstellation resolves the active vault constellation for the agent's
// user-secret ops via the directory (GET /api/v1/vaults — the same source
// container apps and the SDK use), falling back to the built-in defaults if it
// is unreachable. Mirrors the CLI's resolveConstellation.
func mcpConstellation(ctx context.Context, d Deps) (endpoints []string, mrenclave, attServer string) {
	endpoints, mrenclave, attServer = secrets.DefaultEndpoints, secrets.DefaultMRENCLAVE, secrets.DefaultAttServer
	if dir, err := d.Client.VaultDirectory(ctx); err == nil {
		if len(dir.Endpoints) > 0 {
			endpoints = dir.Endpoints
		}
		if dir.MRENCLAVE != "" {
			mrenclave = dir.MRENCLAVE
		}
		if dir.AttestationServer != "" {
			attServer = dir.AttestationServer
		}
	}
	return endpoints, mrenclave, attServer
}

// primaryVaultKeyType returns the key_type of a key's current primary version
// (used by vault_key_rotate to generate the right new material).
func primaryVaultKeyType(ctx context.Context, d Deps, vaultID, name string) (string, error) {
	keys, err := d.Client.ListVaultKeys(ctx, vaultID)
	if err != nil {
		return "", err
	}
	best, bestV := "", -1
	for _, k := range keys {
		if fmt.Sprintf("%v", k["name"]) != name {
			continue
		}
		v := 0
		if vf, ok := k["version"].(float64); ok {
			v = int(vf)
		}
		if v > bestV {
			bestV = v
			best, _ = k["key_type"].(string)
		}
	}
	if bestV < 0 {
		return "", fmt.Errorf("key %q not found in vault %s", name, vaultID)
	}
	return best, nil
}

// functionByRole returns the first app-schema function with the given role
// (config | action | status). Used by apps_configure/apps_action to find the
// image-declared config/action tools.
func functionByRole(schema map[string]interface{}, role string) map[string]interface{} {
	fns, _ := schema["functions"].([]interface{})
	for _, f := range fns {
		if fm, ok := f.(map[string]interface{}); ok && fmt.Sprintf("%v", fm["role"]) == role {
			return fm
		}
	}
	return nil
}

// configRPCName resolves the RPC name to invoke for an app's owner configuration.
// Preferred: the dedicated top-level `configure` section (its `name`, wasm
// `function`, or `endpoint` last segment). Falls back to a legacy role:config
// tool. Returns "" when the app declares no configuration.
func configRPCName(schema map[string]interface{}) string {
	if cfg, ok := schema["configure"].(map[string]interface{}); ok {
		if n, _ := cfg["name"].(string); n != "" {
			return n
		}
		if n, _ := cfg["function"].(string); n != "" {
			return n
		}
		if ep, _ := cfg["endpoint"].(string); ep != "" {
			return strings.TrimPrefix(ep, "/")
		}
	}
	if fn := functionByRole(schema, "config"); fn != nil {
		if n, _ := fn["name"].(string); n != "" {
			return n
		}
	}
	return ""
}

// vaultKeyAddr resolves the constellation addressing for a vault key (mirrors
// the CLI's vaultKeyAddressing): the active directory pin + the key's handle +
// the owner/attestation tokens. Vault key data-plane ops dial the constellation
// directly over RA-TLS (the platform is not in the path).
func vaultKeyAddr(ctx context.Context, d Deps, vaultID, name string, version int) (secrets.VaultOpParams, error) {
	dir, err := d.Client.VaultDirectory(ctx)
	if err != nil {
		return secrets.VaultOpParams{}, err
	}
	keys, err := d.Client.ListVaultKeys(ctx, vaultID)
	if err != nil {
		return secrets.VaultOpParams{}, err
	}
	handle, best := "", -1
	for _, k := range keys {
		if fmt.Sprintf("%v", k["name"]) != name {
			continue
		}
		v := 0
		if vf, ok := k["version"].(float64); ok {
			v = int(vf)
		}
		h, _ := k["handle"].(string)
		if version > 0 {
			if v == version {
				handle = h
				break
			}
			continue
		}
		if v > best {
			best, handle = v, h
		}
	}
	if handle == "" {
		return secrets.VaultOpParams{}, fmt.Errorf("key %q not found in vault %s", name, vaultID)
	}
	ownerTok, err := auth.AccessTokenForAudience(ctx, d.Issuer, "privasys-platform")
	if err != nil {
		return secrets.VaultOpParams{}, err
	}
	attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
	return secrets.VaultOpParams{
		Handle: handle, Endpoints: dir.Endpoints, MRENCLAVE: dir.MRENCLAVE,
		AttServer: dir.AttestationServer, AttToken: attTok, OwnerToken: ownerTok,
	}, nil
}

func containerPath(app map[string]interface{}, function string) string {
	if mcp, ok := app["container_mcp"].(map[string]interface{}); ok {
		if tools, ok := mcp["tools"].([]interface{}); ok {
			for _, t := range tools {
				if tm, ok := t.(map[string]interface{}); ok {
					if n, _ := tm["name"].(string); n == function {
						if ep, _ := tm["endpoint"].(string); ep != "" {
							return ep
						}
					}
				}
			}
		}
	}
	return "/" + function
}
