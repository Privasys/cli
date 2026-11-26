// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	rc "enclave-os-mini/clients/go/ratls"
)

func validManagerParams() ManagerParams {
	reg := func(b byte) []byte { return bytes.Repeat([]byte{b}, tdxRegisterLen) }
	return ManagerParams{
		Host: "127.0.0.1", ServerName: "eu-1-mgr.apps.example",
		EnclaveID: bytes.Repeat([]byte{7}, 16),
		MRTD:      reg(1), RTMR1: reg(2), RTMR2: reg(3),
		AttServerURL: "https://as.example/verify", AttServerTok: "att",
		Path: "/api/v1/containers/app/logs?stream=stderr", Bearer: "owner-bearer",
	}
}

func TestManagerPolicyPinsTheEnclave(t *testing.T) {
	p := validManagerParams()
	pol, err := managerPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if pol.TEE != rc.TeeTypeTDX || !bytes.Equal(pol.MRTD, p.MRTD) || !bytes.Equal(pol.RTMR1, p.RTMR1) ||
		!bytes.Equal(pol.RTMR2, p.RTMR2) || pol.AllowDebugImages || pol.QuoteVerification == nil {
		t.Errorf("policy = %+v", pol)
	}
	if len(pol.ExpectedOids) != 1 || pol.ExpectedOids[0].OID != rc.OidEnclaveInstanceID ||
		!bytes.Equal(pol.ExpectedOids[0].ExpectedValue, p.EnclaveID) {
		t.Errorf("expected OIDs = %+v", pol.ExpectedOids)
	}
	if o := managerOptions(p); o.Trust != rc.TrustFleet || o.Attestation != rc.AttestationChallenge || len(o.Context) != rc.ContextLen {
		t.Errorf("options = %+v", o)
	}
}

// Anything missing that the check needs stops the read before a connection.
func TestManagerGetRefusesWithoutAFullPin(t *testing.T) {
	for name, mutate := range map[string]func(*ManagerParams){
		"no enclave id": func(p *ManagerParams) { p.EnclaveID = nil },
		"no MRTD":       func(p *ManagerParams) { p.MRTD = nil },
		"short RTMR1":   func(p *ManagerParams) { p.RTMR1 = p.RTMR1[:10] },
		"no RTMR2":      func(p *ManagerParams) { p.RTMR2 = nil },
		"no att token":  func(p *ManagerParams) { p.AttServerTok = "" },
	} {
		p := validManagerParams()
		mutate(&p)
		p.Host = "192.0.2.1" // TEST-NET-1: never dialled
		if _, err := ManagerGet(context.Background(), p, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: not refused", name)
		}
	}
}

// A server whose chain does not reach the Privasys fleet anchors (here an
// ordinary self-signed test certificate) is refused, and is sent nothing.
func TestManagerGetRefusesAForeignChain(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("logs"))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p := validManagerParams()
	p.Host = host
	p.Port, _ = strconv.Atoi(port)
	var out bytes.Buffer
	if _, err := ManagerGet(context.Background(), p, &out); err == nil {
		t.Fatal("a foreign chain was accepted")
	}
	if n := requests.Load(); n != 0 || out.Len() != 0 {
		t.Errorf("%d requests reached the server, %d bytes written", n, out.Len())
	}
}
