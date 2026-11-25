// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

// CallParams configures a direct app call.
type CallParams struct {
	Host       string // enclave gateway FQDN
	ServerName string // SNI + Host header (the workload hostname)
	AppName    string // wasm app name (connect_call.app)
	AppType    string // "container" or "wasm"
	Function   string
	Path       string // container endpoint path (default "/"+Function)
	Method     string // container HTTP method (default POST; see CallMethod)
	Body       []byte // raw JSON request body (may be nil)
	AppToken   string // user JWT presented as app_auth / Bearer
	// Headers are extra request headers for a container call (an app's own
	// protocol headers, e.g. X-Privasys-Reproducibility: strict). Ignored for
	// wasm, whose connect_call carries no headers.
	Headers      map[string][]string
	Challenge    []byte // non-empty selects challenge mode (evidence bound to the connection)
	AttServerURL string // set (with AttServerTok) to verify the quote remotely
	AttServerTok string
}

// Call verifies the enclave (RA-TLS challenge + report-data binding; plus a
// remote quote verification when AttServerURL/Tok are set) and, only if
// verification passes, sends the request directly to the app — the control
// plane is never in the data path. Container responses (incl. chunked/SSE)
// stream to out; the response status is returned.
func Call(ctx context.Context, p CallParams, out io.Writer) (int, error) {
	opts := &rc.Options{ServerName: p.ServerName, Timeout: 60 * time.Second, Attestation: rc.AttestationDeterministic}
	if len(p.Challenge) > 0 {
		opts.Attestation = rc.AttestationChallenge
		if len(p.Challenge) == rc.ContextLen {
			// A 32-byte challenge becomes the context itself, so the evidence
			// commits to the value the caller chose.
			opts.Context = p.Challenge
		}
	}
	client, err := rc.Connect(p.Host, 443, opts)
	if err != nil {
		return 0, fmt.Errorf("RA-TLS connect to %s: %w", p.Host, err)
	}
	defer client.Close()

	// Verify the enclave BEFORE sending any application data (RA-TLS v2: the
	// evidence was obtained after the handshake; this checks it).
	policy := &rc.VerificationPolicy{TEE: teeOf(client.Evidence())}
	if p.AttServerURL != "" && p.AttServerTok != "" {
		policy.QuoteVerification = &rc.QuoteVerificationConfig{Endpoint: p.AttServerURL, Token: p.AttServerTok}
	}
	if _, verr := client.VerifyCertificate(policy); verr != nil {
		return 0, fmt.Errorf("enclave attestation failed — refusing to send data: %w", verr)
	}

	if p.AppType == "container" {
		path := p.Path
		if path == "" {
			path = "/" + p.Function
		}
		hdr := http.Header{}
		for k, vs := range p.Headers {
			for _, v := range vs {
				hdr.Add(k, v)
			}
		}
		if p.AppToken != "" {
			hdr.Set("Authorization", "Bearer "+p.AppToken)
		}
		method := p.Method
		if method == "" {
			method = http.MethodPost
		}
		resp, err := client.HTTPDoHeader(method, path, p.ServerName, p.Body, hdr)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(out, resp.Body)
		return resp.StatusCode, nil
	}

	// WASM: connect_call needs no platform role (auth rides in app_auth).
	var parsed interface{} = map[string]interface{}{}
	if len(p.Body) > 0 {
		if err := json.Unmarshal(p.Body, &parsed); err != nil {
			return 0, fmt.Errorf("request body is not valid JSON: %w", err)
		}
	}
	connectCall := map[string]interface{}{"app": p.AppName, "function": p.Function, "body": parsed}
	if p.AppToken != "" {
		connectCall["app_auth"] = p.AppToken
	}
	payload, _ := json.Marshal(map[string]interface{}{"connect_call": connectCall})
	body, err := client.SendData(payload, "")
	if err != nil {
		return 0, err
	}
	_, _ = out.Write(body)
	return 200, nil
}

// ConfigureEndpoint is the configure endpoint a container app declares in its
// manifest (container_mcp.configure.endpoint), or "" when it declares none.
func ConfigureEndpoint(app map[string]interface{}) string {
	mcp, _ := app["container_mcp"].(map[string]interface{})
	cfg, _ := mcp["configure"].(map[string]interface{})
	ep, _ := cfg["endpoint"].(string)
	return ep
}

// IsConfigureEndpoint reports whether path is the configure endpoint the app
// declares.
func IsConfigureEndpoint(app map[string]interface{}, path string) bool {
	ep := ConfigureEndpoint(app)
	return ep != "" && samePath(path, ep)
}

// CallMethod is the HTTP method of a container call. With no method given it
// is POST, as it always was, except to the app's configure endpoint with no
// body: that POSTs an empty configuration, which an app may take as "reset my
// settings" (four dev connectors lost theirs to a call meant as a read), so it
// is refused and the caller must say which one it means.
func CallMethod(method string, body []byte, path, configurePath string) (string, error) {
	m := strings.ToUpper(strings.TrimSpace(method))
	switch m {
	case "":
		if len(body) == 0 && configurePath != "" && samePath(path, configurePath) {
			return "", fmt.Errorf("%s is the app's configure endpoint, and a call to it with no data POSTs an empty configuration, "+
				"which can reset the app's settings; set the method to GET to read it, give data to write it, "+
				"or set the method to POST to send an empty body on purpose", path)
		}
		return http.MethodPost, nil
	case http.MethodGet, http.MethodHead:
		if len(body) > 0 {
			return "", fmt.Errorf("a %s carries no body; drop the data or use another method", m)
		}
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return "", fmt.Errorf("method %q is not one of GET, HEAD, POST, PUT, PATCH, DELETE", method)
	}
	return m, nil
}

// samePath compares two endpoint paths, ignoring a query and a trailing slash.
func samePath(a, b string) bool {
	norm := func(s string) string {
		s, _, _ = strings.Cut(strings.TrimSpace(s), "?")
		if !strings.HasPrefix(s, "/") {
			s = "/" + s
		}
		if len(s) > 1 {
			s = strings.TrimRight(s, "/")
		}
		return s
	}
	return norm(a) == norm(b)
}
