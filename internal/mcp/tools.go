// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/ratls"
	"github.com/Privasys/cli/internal/secrets"
)

var (
	errNoVersions  = errors.New("app has no versions; create one first")
	errPickEnclave = errors.New("multiple or no compatible enclaves; pass 'enclave' explicitly")
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
				return secrets.Create(ctx, secrets.CreateParams{
					Issuer: d.Issuer, Bearer: d.Token, Sub: sub,
					Handle: "users/" + sub + "/" + name, Secret: material, Exportable: exportable,
					Endpoints: secrets.DefaultEndpoints, Threshold: 2,
					MRENCLAVE: secrets.DefaultMRENCLAVE, AttServer: secrets.DefaultAttServer, AttToken: attTok,
				})
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
			Description: "Deploy a version of an app to an enclave (defaults to latest version and the sole compatible enclave).",
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
				enclaveID := argStr(args, "enclave")
				if enclaveID == "" {
					encs, err := d.Client.CompatibleEnclaves(ctx, id)
					if err != nil {
						return nil, err
					}
					if len(encs) != 1 {
						return nil, errPickEnclave
					}
					enclaveID, _ = encs[0]["id"].(string)
				}
				return d.Client.DeployVersion(ctx, id, versionID, enclaveID)
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
