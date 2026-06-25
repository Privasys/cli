# Confidential computing

**The problem.** Normal cloud computing encrypts data at rest (on disk) and in
transit (TLS), but to *process* it the CPU must decrypt it into memory. While it
sits in memory the infrastructure operator, a compromised hypervisor, a malicious
co-tenant, or an insider can read it. For sensitive workloads (health, finance,
identity, private user data) that exposure window is the whole problem.

**The answer: encrypted in use.** Confidential computing uses a hardware
**Trusted Execution Environment (TEE)** to keep data encrypted in memory and
isolated from everything outside the TEE, including the host OS and hypervisor.
The CPU decrypts only inside the protected boundary; the operator never sees
plaintext.

**TEE flavours Privasys uses:**
- **Intel SGX** — process-level enclaves with a very small trust boundary. Used
  by Enclave OS Mini for WASM modules (TCB roughly a few MB).
- **Intel TDX** — a whole confidential VM with encrypted memory. Used by Enclave
  OS Virtual to run standard containers unmodified.
- **AMD SEV-SNP** — AMD's confidential VM technology (also supported).

**The part people miss: encryption is not enough.** A "confidential VM" with
encrypted memory still leaves gaps unless you also have:
1. **Attestation** — hardware-signed proof of *which* code and configuration are
   running, so you do not just trust the operator's word. See `ra-tls.md`.
2. **A measured, verified boot chain and disk integrity** — otherwise the code
   inside the encrypted VM could have been tampered with before it started.

Privasys closes those gaps: hardened images with verified filesystems and
authenticated disk encryption, every component measured at boot, and that
evidence delivered to clients over a normal TLS handshake. The pitch is not
"trust us, it is private" but "here is the hardware proof, verify it yourself."

More: [docs.privasys.org/solutions/enclave-os](https://docs.privasys.org/solutions/enclave-os).
