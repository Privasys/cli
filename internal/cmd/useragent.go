// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"net/http"
	"runtime"
)

// userAgent names this CLI on every HTTP request it makes, so the control
// plane's and privasys.id's logs can tell which client and release asked:
// "privasys/<version> (<os>; <arch>)".
func userAgent() string {
	return "privasys/" + Version + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"
}

// uaTransport sets the CLI's User-Agent on requests that name none.
type uaTransport struct {
	base http.RoundTripper
	ua   string
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") != "" {
		return t.base.RoundTrip(req)
	}
	r := req.Clone(req.Context()) // a RoundTripper must not change the caller's request
	r.Header.Set("User-Agent", t.ua)
	return t.base.RoundTrip(r)
}

// installUserAgent wraps the default transport, which every HTTP client of
// the CLI and its MCP server uses (none sets a transport of its own).
func installUserAgent() {
	if _, done := http.DefaultTransport.(*uaTransport); done {
		return
	}
	http.DefaultTransport = &uaTransport{base: http.DefaultTransport, ua: userAgent()}
}
