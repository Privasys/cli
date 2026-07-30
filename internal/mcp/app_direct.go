// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/Privasys/cli/internal/ratls"
)

// callAppDirect invokes one app tool over RA-TLS, straight to the enclave.
//
// The owner tools (apps_configure, apps_action) used the control-plane relay
// `POST /apps/{id}/rpc/{fn}`, which is being retired: the caller got no
// attestation from it, and its 1 MiB control-plane body cap applied to app
// data. Here the enclave's quote and report-data binding are verified before
// any application bytes go out, and mgmt is consulted for metadata only.
//
// Note that mgmt therefore no longer observes a wasm configure, and wasm has no
// probe, so a caller configuring a wasm app should also report
// `POST /apps/{id}/config-complete` or the portal keeps showing Frozen.
func callAppDirect(ctx context.Context, d Deps, appID, fn string, body interface{}) (map[string]interface{}, error) {
	app, err := d.Client.GetApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	name, _ := app["name"].(string)
	aType, _ := app["app_type"].(string)
	if aType == "" {
		aType = "wasm"
	}
	path := ""
	if aType == "container" {
		path = containerPath(app, fn)
	}
	host, err := d.Client.ActiveDeploymentHost(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("%w — the app must be deployed to call it", err)
	}
	var raw []byte
	if body != nil {
		if raw, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("request body could not be encoded: %w", err)
		}
	}

	var buf bytes.Buffer
	status, err := ratls.Call(ctx, ratls.CallParams{
		Host: host, ServerName: host, AppName: name, AppType: aType,
		Function: fn, Path: path, Body: raw, AppToken: d.Token,
		Challenge: ratls.NewNonce(),
	}, &buf)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if b := buf.Bytes(); len(b) > 0 {
		if jerr := json.Unmarshal(b, &out); jerr != nil {
			if status >= 400 {
				return nil, fmt.Errorf("app returned status %d: %s", status, string(b))
			}
			return map[string]interface{}{"response": string(b)}, nil
		}
	}
	if status >= 400 {
		if msg, _ := out["error"].(string); msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, fmt.Errorf("app returned status %d", status)
	}
	return out, nil
}
