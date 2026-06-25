# RA-TLS (Remote-Attestation TLS)

RA-TLS is how a client gets hardware proof of what it is talking to, during an
ordinary TLS handshake. No custom protocol, no SDK required, no blind trust.

## The idea

The enclave generates its TLS key pair *inside* the TEE. When it makes its leaf
certificate, it asks the hardware for an attestation **quote** (a signed
measurement of the code + configuration running) and embeds that quote, plus a
set of Privasys-defined X.509 extensions, into the certificate. The certificate's
public key is bound into the quote's `report_data`, so the quote provably belongs
to *this* certificate, not a replayed one.

When a client connects, it does a normal TLS handshake, then:
1. verifies the quote's signature chains to genuine Intel/AMD hardware (via the
   attestation server),
2. checks the measurement (MRENCLAVE for SGX, MRTD/RTMRs for TDX) against what it
   expects, and
3. checks the `report_data` binding ties the quote to the certificate it was
   handed.

If all three hold, the client knows it is talking to specific, unmodified code on
genuine confidential hardware.

## Challenge / freshness

To stop an attacker replaying an old quote, the client can send a fresh **nonce**;
the enclave folds it into `report_data` (`SHA-512(SHA-256(pubkey) || nonce)`) and
re-issues the certificate for that connection. The `privasys attest` command and
`attest` MCP tool do exactly this: a fresh-nonce challenge plus a quote check
against the attestation server.

## The OID extensions

Under the arc `1.3.6.1.4.1.65230`, the certificate also carries the platform and
per-workload bindings: the config merkle root, the combined-workloads hash, the
per-workload **code hash** (the hash of the exact WASM or the container image
digest), the image reference, and more. These let a verifier confirm not just
"genuine hardware" but "the specific code I audited".

## Why it matters

The data plane is direct: `privasys apps call` connects to the enclave over
RA-TLS and streams the response; the control plane is never in the path. So when
you call an attested app, you are talking to verified hardware running verified
code, end to end.

More: [docs.privasys.org/solutions/enclave-os/attestation/ra-tls](https://docs.privasys.org/solutions/enclave-os/attestation/ra-tls).
