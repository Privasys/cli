# How Privasys works

Privasys is a platform for deploying applications that run inside hardware TEEs
and prove what they are running. You bring code; the platform handles hardware,
attestation, networking, and encrypted storage.

## Two ways to run

- **WASM module** — your code is compiled to WebAssembly and runs inside an
  **Intel SGX** enclave (Enclave OS Mini). Smallest trust boundary (a few MB);
  the enclave hashes your binary and binds that hash into every certificate, so
  clients can check the exact code.
- **Container** — your existing container image runs inside a **confidential VM**
  (Intel TDX, Enclave OS Virtual). No code changes; standard Linux and tooling.
  Best for existing apps, databases, AI inference.

Both get the same guarantees: hardware-protected memory, RA-TLS certificates that
carry attestation, and optional encrypted storage.

## The pieces

- **Enclave OS** — the confidential OS the apps run in (Mini for SGX, Virtual for
  CVMs). Hardened, measured at boot.
- **Attestation server** (`as.privasys.org`) — independently verifies TEE quotes
  from Intel/AMD and the platform's certificate chain.
- **Gateway** — a transparent Layer-4 proxy. It reads only the TLS SNI header to
  route `*.apps.privasys.org` traffic to the right enclave and splices the
  connection through. It never terminates TLS and never sees plaintext;
  encryption ends *inside* the enclave.
- **Reproducible builds** — link a GitHub commit and the platform builds it via
  automated pipelines so anyone can rebuild from source and check the deployed
  binary matches bit-for-bit. No hidden steps.
- **MCP per app** — every deployed app is automatically an attested Model Context
  Protocol tool server: WASM tools are derived from the code's typed interface,
  containers declare tools in a `privasys.json` manifest. AI agents discover and
  call them with hardware attestation on every connection.

## How a client trusts an app

A client (the CLI, a verification library, a browser via session-relay) connects
over RA-TLS, the certificate carries the hardware quote + the app's code hash,
and the client verifies it during the normal handshake. Trust is based on
hardware proof, not on trusting Privasys. See `ra-tls.md`.

More: [docs.privasys.org/solutions/platform/overview](https://docs.privasys.org/solutions/platform/overview).
