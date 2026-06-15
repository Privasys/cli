// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/ratls"
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
				"port":         intProp("container port"),
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
				if p := argInt(args, "port"); p != 0 {
					body["container_port"] = p
				}
				return d.Client.CreateApp(ctx, body)
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
				host, _ := app["hostname"].(string)
				if host == "" {
					return nil, errors.New("app has no hostname (not deployed?)")
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
				attTok, _ := auth.AccessTokenForAudience(ctx, d.Issuer, "attestation-server")
				res, err := ratls.Call(ctx, ratls.CallParams{
					Host: host, ServerName: host, AppName: name, AppType: aType,
					Function: fn, Path: path, Body: body, AppToken: d.Token,
					Challenge: ratls.NewNonce(), AttServerURL: "https://as.privasys.org/verify", AttServerTok: attTok,
				})
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"status": res.Status, "body": string(res.Body)}, nil
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
					app, err := d.Client.GetApp(ctx, id)
					if err != nil {
						return nil, err
					}
					if h, ok := app["hostname"].(string); ok {
						host = h
					}
					if host == "" {
						return nil, errors.New("could not resolve app hostname; pass 'host'")
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
