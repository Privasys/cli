---
name: privasys
description: How to deploy, call, and verify confidential apps on the Privasys platform using the privasys MCP tools and CLI. Use when the user wants to ship, run, attest, or manage a confidential-computing workload, or manage their Privasys account, team, or billing.
---

# Working with Privasys

[Privasys](https://privasys.org) runs apps inside hardware-attested enclaves (Intel SGX/TDX, AMD SEV-SNP). The `privasys` binary is both a CLI and an MCP server (`privasys mcp serve`); prefer the MCP tools when one fits, fall back to the CLI otherwise.

## Authentication

- Human: `privasys auth login` (wallet QR, or passkey/social in the browser). The signing key never leaves the wallet.
- Unattended (CI / agents): set `PRIVASYS_SERVICE_KEY` to a service-account key. The `whoami` tool reports the current identity.
- Never ask the user for, store, or print credentials. Tokens live in the OS keychain.

## The core loop

1. `apps_create` — register an app (from a GitHub commit; builds are reproducible).
2. `apps_deploy` (watch to completion) — roll out a version.
3. `apps_call` — invoke an app API. The data plane is **direct**: the call goes to the enclave over RA-TLS, not through the control plane. Responses stream.
4. `attest` — challenge the enclave with a fresh nonce and verify its TEE quote against the attestation server.

## The rule that matters

**Attestation is the product.** Before telling a user an endpoint is ready, trustworthy, or safe to send data to, run `attest` and confirm it passed (measurement known, TCB up to date). If attestation fails, say so directly and treat the endpoint as untrusted. Do not paper over a failed quote.

## Other surfaces

- `account_*`, `team_*` — account and member management.
- `billing_*` — balance, usage, ledger; subscribe/buy-credits return Stripe URLs (no card data ever touches the CLI).

## Conventions

- Apps are addressable by **name or id** interchangeably.
- Every CLI command supports `--format json`; output auto-switches to JSON when piped. `--no-input` never prompts.
- Exit codes: `0` ok, `3` not authenticated, `4` not authorized, `5` not found.
