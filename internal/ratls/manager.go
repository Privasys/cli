// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

// tdxRegisterLen is the length of a TDX measurement register.
const tdxRegisterLen = 48

// ManagerParams configures a read from an enclave's manager.
type ManagerParams struct {
	Host       string // address to dial (the enclave's gateway host)
	Port       int    // 0 = 443
	ServerName string // SNI + Host header: "<enclave>-mgr.<app domain>"
	// EnclaveID is the control plane's enclave id (16-byte UUID): the
	// manager's certificate must carry it (OID 1.3).
	EnclaveID []byte
	// MRTD, RTMR1 and RTMR2 are the measurements the control plane records
	// for that enclave's runtime: the quote must match all three, so only our
	// runtime on that enclave is sent the bearer, not any TD that claims its id.
	MRTD, RTMR1, RTMR2 []byte
	AttServerURL       string // required: the quote is verified remotely
	AttServerTok       string
	Path               string // request path, with its query
	Bearer             string // the caller's own platform token
	// MaxBytes caps what is read from the body (0 = no cap).
	MaxBytes int64
}

// managerPolicy is everything the manager must prove before it is sent the
// bearer: a TDX quote verified by the attestation server, the recorded
// runtime measurements, a production image, and the enclave id. The chain to
// the Privasys fleet anchors is checked during the handshake (managerOptions).
func managerPolicy(p ManagerParams) (*rc.VerificationPolicy, error) {
	if len(p.EnclaveID) != 16 {
		return nil, errors.New("the enclave id is not a 16-byte UUID")
	}
	for name, v := range map[string][]byte{"MRTD": p.MRTD, "RTMR1": p.RTMR1, "RTMR2": p.RTMR2} {
		if len(v) != tdxRegisterLen {
			return nil, fmt.Errorf("the platform gave no %d-byte %s for the enclave", tdxRegisterLen, name)
		}
	}
	if p.AttServerURL == "" || p.AttServerTok == "" {
		return nil, errors.New("no attestation server token")
	}
	return &rc.VerificationPolicy{
		TEE:  rc.TeeTypeTDX,
		MRTD: p.MRTD, RTMR1: p.RTMR1, RTMR2: p.RTMR2,
		QuoteVerification: &rc.QuoteVerificationConfig{Endpoint: p.AttServerURL, Token: p.AttServerTok},
		ExpectedOids:      []rc.ExpectedOid{{OID: rc.OidEnclaveInstanceID, ExpectedValue: p.EnclaveID}},
		// AllowDebugImages stays false: a non-production image is refused.
	}, nil
}

// managerOptions dial in challenge mode with a fresh context, and require the
// chain to reach the Privasys fleet anchors.
func managerOptions(p ManagerParams) *rc.Options {
	return &rc.Options{ServerName: p.ServerName, Timeout: 60 * time.Second,
		Attestation: rc.AttestationChallenge, Context: NewNonce(), Trust: rc.TrustFleet}
}

// ManagerGet attests the manager and, only once its chain, quote,
// measurements and enclave id all verify, sends one GET with the caller's
// bearer. A 200 body is copied to out; any other status is returned with no
// body written.
func ManagerGet(ctx context.Context, p ManagerParams, out io.Writer) (int, error) {
	policy, err := managerPolicy(p)
	if err != nil {
		return 0, fmt.Errorf("the enclave manager cannot be verified, so nothing was sent: %w", err)
	}
	port := p.Port
	if port == 0 {
		port = 443
	}
	client, err := rc.Connect(p.Host, port, managerOptions(p))
	if err != nil {
		return 0, fmt.Errorf("RA-TLS connect to %s (%s): %w", p.ServerName, p.Host, err)
	}
	defer client.Close()
	if _, verr := client.VerifyCertificate(policy); verr != nil {
		return 0, fmt.Errorf("the manager's attestation failed, refusing to send anything: %w", verr)
	}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+p.Bearer)
	resp, err := client.HTTPDoHeader(http.MethodGet, p.Path, p.ServerName, nil, hdr)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var body io.Reader = resp.Body
	if p.MaxBytes > 0 {
		body = io.LimitReader(resp.Body, p.MaxBytes)
	}
	_, err = io.Copy(out, body)
	return resp.StatusCode, err
}
