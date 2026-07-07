// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package ratls is the CLI's client-side RA-TLS verifier. It connects directly
// to an enclave (through the gateway's L4 splice), optionally challenges it
// with a fresh nonce (0xFFBB, requires the Privasys Go fork + -tags ratls),
// and verifies the attestation quote against the attestation server — so the
// CLI trusts the enclave's hardware attestation, not the control plane.
package ratls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	rc "enclave-os-mini/clients/go/ratls"
)

// OID is a parsed certificate OID extension.
type OID struct {
	OID      string `json:"oid"`
	Label    string `json:"label"`
	ValueHex string `json:"value_hex"`
}

// Result is the outcome of a direct, client-side attestation.
type Result struct {
	Host          string   `json:"host"`
	TLSVersion    string   `json:"tls_version"`
	CipherSuite   string   `json:"cipher_suite"`
	Challenged    bool     `json:"challenged"`
	NonceHex      string   `json:"nonce_hex,omitempty"`
	QuoteType     string   `json:"quote_type"`
	QuoteOID      string   `json:"quote_oid"`
	ReportDataHex string   `json:"report_data_hex,omitempty"`
	PubKeySHA256  string   `json:"pubkey_sha256"`
	CustomOIDs    []OID    `json:"custom_oids,omitempty"`
	QuoteStatus   string   `json:"quote_status,omitempty"`
	TcbDate       string   `json:"tcb_date,omitempty"`
	AdvisoryIDs   []string `json:"advisory_ids,omitempty"`
	GPU           *GPU     `json:"gpu,omitempty"`
	Verified      bool     `json:"verified"`
	VerifyError   string   `json:"verify_error,omitempty"`
	CertPEM       string   `json:"-"`
	QuoteRaw      []byte   `json:"-"`
}

// GPU is the NVIDIA Confidential-Computing attestation verdict, present when the
// enclave's certificate carries GPU evidence (the tdx-gpu combined case) and it
// was verified against the attestation server.
type GPU struct {
	Verified bool `json:"verified"`
	// MeasurementsVerified is true only once firmware/VBIOS measurements are
	// matched against a signed NVIDIA RIM. Verified can hold (genuine device,
	// CC mode, authentic report) while this is still false.
	MeasurementsVerified bool   `json:"measurements_verified"`
	UUID                 string `json:"uuid,omitempty"`
	Driver               string `json:"driver,omitempty"`
	VBIOS                string `json:"vbios,omitempty"`
	CCEnvironment        string `json:"cc_environment,omitempty"`
}

// Params configures a direct verification.
type Params struct {
	Host          string // enclave gateway FQDN
	Port          int    // usually 443
	ServerName    string // SNI (the workload hostname)
	Challenge     []byte // nil => deterministic mode
	AttServerURL  string // attestation server verify endpoint (quote verification)
	AttServerTok  string // optional bearer for the attestation server
	ExpectMRENCLA string // optional MRENCLAVE pin (hex)
	ExpectMRTD    string // optional MRTD pin (hex)
}

// NewNonce returns a 32-byte random challenge nonce.
func NewNonce() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func teeFromOID(oid string) rc.TeeType {
	switch oid {
	case rc.OidTDXQuote:
		return rc.TeeTypeTDX
	case rc.OidSEVSNPReport:
		return rc.TeeTypeSEVSNP
	case rc.OidNVIDIAGPUEvidence:
		return rc.TeeTypeNVIDIAGPU
	default:
		return rc.TeeTypeSGX
	}
}

// Verify connects to the enclave, (optionally) challenges it, and verifies its
// RA-TLS certificate. The returned Result is populated even when verification
// fails (VerifyError set, Verified false) so callers can show what was seen.
func Verify(ctx context.Context, p Params) (*Result, error) {
	if p.Port == 0 {
		p.Port = 443
	}
	opts := &rc.Options{ServerName: p.ServerName, Timeout: 20 * time.Second}
	if len(p.Challenge) > 0 {
		opts.Challenge = p.Challenge
	}
	client, err := rc.Connect(p.Host, p.Port, opts)
	if err != nil {
		return nil, fmt.Errorf("RA-TLS connect to %s:%d: %w", p.Host, p.Port, err)
	}
	defer client.Close()

	res := &Result{
		Host:        fmt.Sprintf("%s:%d", p.Host, p.Port),
		TLSVersion:  client.TLSVersion(),
		CipherSuite: client.CipherSuite(),
		Challenged:  len(p.Challenge) > 0,
	}
	if res.Challenged {
		res.NonceHex = hex.EncodeToString(p.Challenge)
	}
	if ders := client.PeerCertificatesDER(); len(ders) > 0 {
		res.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ders[0]}))
	}

	// Detect the TEE from the cert's quote OID so the policy enforces the
	// right quote type (policy.TEE defaults to SGX).
	pre := client.InspectCert()
	oid := ""
	if pre.Quote != nil {
		oid = pre.Quote.OID
	}

	policy := &rc.VerificationPolicy{TEE: teeFromOID(oid)}
	if len(p.Challenge) > 0 {
		policy.ReportData = rc.ReportDataChallengeResponse
		policy.Nonce = p.Challenge
	} else {
		policy.ReportData = rc.ReportDataDeterministic
	}
	if p.AttServerURL != "" {
		policy.QuoteVerification = &rc.QuoteVerificationConfig{Endpoint: p.AttServerURL, Token: p.AttServerTok}
	}
	if p.ExpectMRENCLA != "" {
		if b, e := hex.DecodeString(p.ExpectMRENCLA); e == nil {
			policy.MRENCLAVE = b
		}
	}
	if p.ExpectMRTD != "" {
		if b, e := hex.DecodeString(p.ExpectMRTD); e == nil {
			policy.MRTD = b
		}
	}

	info, verr := client.VerifyCertificate(policy)
	if verr != nil {
		res.VerifyError = verr.Error()
		info = pre // fall back to the unverified inspection for display
	} else {
		res.Verified = true
	}

	fill(res, info)
	return res, nil
}

func fill(res *Result, info rc.CertInfo) {
	res.PubKeySHA256 = info.PubKeySHA256
	if info.Quote != nil {
		res.QuoteOID = info.Quote.OID
		res.QuoteType = info.Quote.Label
		res.ReportDataHex = hex.EncodeToString(info.Quote.ReportData)
		res.QuoteRaw = info.Quote.Raw
	}
	for _, o := range info.CustomOids {
		res.CustomOIDs = append(res.CustomOIDs, OID{OID: o.OID, Label: o.Label, ValueHex: hex.EncodeToString(o.Value)})
	}
	if info.QuoteVerification != nil {
		res.QuoteStatus = string(info.QuoteVerification.Status)
		res.TcbDate = info.QuoteVerification.TcbDate
		res.AdvisoryIDs = info.QuoteVerification.AdvisoryIDs
	}
	if info.GPUAttestation != nil {
		res.GPU = &GPU{
			Verified:             info.GPUAttestation.Verified,
			MeasurementsVerified: info.GPUAttestation.MeasurementsVerified,
			UUID:                 info.GPUAttestation.GPUUUID,
			Driver:               info.GPUAttestation.Driver,
			VBIOS:                info.GPUAttestation.VBIOS,
			CCEnvironment:        info.GPUAttestation.CCEnvironment,
		}
	}
}
