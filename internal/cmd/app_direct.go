// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/output"
	"github.com/Privasys/cli/internal/ratls"
)

// callAppDirect invokes one app tool over RA-TLS, straight to the enclave.
//
// Owner operations — configure, actions, their status polling — used to go
// through the control-plane relay (`POST /apps/{id}/rpc/{fn}`). That relay is
// being retired: it gave the caller no attestation, since the management
// service terminated the connection and the client verified nothing, and it
// applied a control-plane 1 MiB body cap to app data, which is what stopped a
// CSCA master list from being configured through it.
//
// This path verifies the enclave's quote and report-data binding BEFORE any
// application bytes are sent, then talks to the app directly. mgmt is consulted
// only for metadata: the app's type, name, manifest path and deployment host.
//
// One consequence worth knowing: mgmt no longer observes a wasm configure, and
// wasm has no probe, so a caller that configures a wasm app should report it
// with `POST /apps/{id}/config-complete` or the portal keeps showing Frozen.
func callAppDirect(ctx context.Context, env *Env, client *api.Client, appID, fn string, body interface{}) (map[string]interface{}, error) {
	app, err := client.GetApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	appName := output.Str(app, "name")
	aType := appType(app)
	if aType == "" {
		aType = "wasm"
	}
	path := ""
	if aType == "container" {
		path = resolveContainerPath(app, fn)
	}
	host, err := client.ActiveDeploymentHost(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("%w — the app must be deployed to call it", err)
	}
	appTok, err := auth.AccessToken(ctx, env.Cfg.Issuer)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if body != nil {
		if raw, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("request body could not be encoded: %w", err)
		}
	}

	var buf bytes.Buffer
	status, err := ratls.Call(ctx, ratls.CallParams{
		Host: host, ServerName: host, AppName: appName, AppType: aType,
		Function: fn, Path: path, Body: raw, AppToken: appTok,
		// A fresh nonce binds the quote to THIS connection, so a replayed
		// certificate cannot stand in for a live enclave.
		Challenge: ratls.NewNonce(),
	}, &buf)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if b := buf.Bytes(); len(b) > 0 {
		if jerr := json.Unmarshal(b, &out); jerr != nil {
			// Not JSON: hand back what the app said rather than hiding it.
			if status >= 400 {
				return nil, fmt.Errorf("app returned status %d: %s", status, firstLineOf(b))
			}
			return map[string]interface{}{"response": string(b)}, nil
		}
	}
	if status >= 400 {
		if msg := output.Str(out, "error"); msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, fmt.Errorf("app returned status %d", status)
	}
	return out, nil
}

// firstLineOf trims a response body to something fit for one error line.
func firstLineOf(b []byte) string {
	s := string(b)
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
