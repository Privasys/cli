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

// ManagerParams configures a read from an enclave's manager.
type ManagerParams struct {
	Host       string // address to dial (the enclave's gateway host)
	ServerName string // SNI + Host header: "<enclave>-mgr.<app domain>"
	// EnclaveID is the control plane's enclave id (16-byte UUID): the
	// manager's certificate must carry it (OID 1.3), or nothing is sent.
	EnclaveID    []byte
	AttServerURL string // required: the quote is verified remotely
	AttServerTok string
	Path         string // request path, with its query
	Bearer       string // the caller's own platform token
	// MaxBytes caps what is read from the body (0 = no cap).
	MaxBytes int64
}

// ManagerGet attests the manager and, only once its quote, its leaf and its
// enclave id all verify, sends one GET with the caller's bearer. A 200 body is
// copied to out; any other status is returned with no body written.
func ManagerGet(ctx context.Context, p ManagerParams, out io.Writer) (int, error) {
	if len(p.EnclaveID) != 16 {
		return 0, errors.New("the enclave id is not a 16-byte UUID: refusing to connect")
	}
	if p.AttServerURL == "" || p.AttServerTok == "" {
		return 0, errors.New("no attestation server token: the manager cannot be verified, so nothing is sent")
	}
	opts := &rc.Options{ServerName: p.ServerName, Timeout: 60 * time.Second,
		Attestation: rc.AttestationChallenge, Context: NewNonce()}
	client, err := rc.Connect(p.Host, 443, opts)
	if err != nil {
		return 0, fmt.Errorf("RA-TLS connect to %s (%s): %w", p.ServerName, p.Host, err)
	}
	defer client.Close()

	policy := &rc.VerificationPolicy{
		TEE:               teeOf(client.Evidence()),
		QuoteVerification: &rc.QuoteVerificationConfig{Endpoint: p.AttServerURL, Token: p.AttServerTok},
		ExpectedOids:      []rc.ExpectedOid{{OID: rc.OidEnclaveInstanceID, ExpectedValue: p.EnclaveID}},
	}
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
