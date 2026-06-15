// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

// CallParams configures a direct app call.
type CallParams struct {
	Host         string // enclave gateway FQDN
	ServerName   string // SNI + Host header (the workload hostname)
	AppName      string // wasm app name (connect_call.app)
	AppType      string // "container" or "wasm"
	Function     string
	Path         string // container endpoint path (default "/"+Function)
	Body         []byte // raw JSON request body (may be nil)
	AppToken     string // user JWT presented as app_auth / Bearer
	Challenge    []byte // verify-before-send nonce
	AttServerURL string
	AttServerTok string
}

// CallResult is a direct app call's response.
type CallResult struct {
	Status int    `json:"status"`
	Body   []byte `json:"-"`
}

// Call verifies the enclave (RA-TLS challenge + quote verification) and, only
// if verification passes, sends the request directly to the app. The control
// plane is never in the data path. It refuses to send to an unattested enclave.
func Call(ctx context.Context, p CallParams) (*CallResult, error) {
	opts := &rc.Options{ServerName: p.ServerName, Timeout: 30 * time.Second}
	if len(p.Challenge) > 0 {
		opts.Challenge = p.Challenge
	}
	client, err := rc.Connect(p.Host, 443, opts)
	if err != nil {
		return nil, fmt.Errorf("RA-TLS connect to %s: %w", p.Host, err)
	}
	defer client.Close()

	// Verify the enclave BEFORE sending any application data.
	info := client.InspectCert()
	oid := ""
	if info.Quote != nil {
		oid = info.Quote.OID
	}
	policy := &rc.VerificationPolicy{TEE: teeFromOID(oid)}
	if len(p.Challenge) > 0 {
		policy.ReportData = rc.ReportDataChallengeResponse
		policy.Nonce = p.Challenge
	} else {
		policy.ReportData = rc.ReportDataDeterministic
	}
	if p.AttServerURL != "" && p.AttServerTok != "" {
		policy.QuoteVerification = &rc.QuoteVerificationConfig{Endpoint: p.AttServerURL, Token: p.AttServerTok}
	}
	if _, verr := client.VerifyCertificate(policy); verr != nil {
		return nil, fmt.Errorf("enclave attestation failed — refusing to send data: %w", verr)
	}

	if p.AppType == "container" {
		path := p.Path
		if path == "" {
			path = "/" + p.Function
		}
		status, body, err := client.HTTPRequest("POST", path, p.ServerName, p.Body, p.AppToken)
		if err != nil {
			return nil, err
		}
		return &CallResult{Status: status, Body: body}, nil
	}

	// WASM: connect_call needs no platform role (auth rides in app_auth).
	var parsed interface{} = map[string]interface{}{}
	if len(p.Body) > 0 {
		if err := json.Unmarshal(p.Body, &parsed); err != nil {
			return nil, fmt.Errorf("request body is not valid JSON: %w", err)
		}
	}
	connectCall := map[string]interface{}{"app": p.AppName, "function": p.Function, "body": parsed}
	if p.AppToken != "" {
		connectCall["app_auth"] = p.AppToken
	}
	payload, _ := json.Marshal(map[string]interface{}{"connect_call": connectCall})
	body, err := client.SendData(payload, "")
	if err != nil {
		return nil, err
	}
	return &CallResult{Status: 200, Body: body}, nil
}
