---
description: Verify the hardware attestation of a Privasys confidential app
argument-hint: "[app name or id]"
---

Verify the enclave behind a Privasys app. Target: $ARGUMENTS

Use the `attest` MCP tool (or `privasys attest <app>`):

1. Run a full attestation: the CLI connects to the enclave directly over RA-TLS, challenges it with a fresh nonce, and verifies the TEE quote against the attestation server.
2. Report the verdict plainly: verified or not, the measurement (MRTD/mrenclave), and the TCB status. If the user gave an expected measurement, compare against it.
3. If verification fails, do not soften it. State that the endpoint must not be trusted and show the failure reason.
