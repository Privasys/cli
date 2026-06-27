---
name: privasys
description: Deploy, call, verify, and explain confidential apps on the Privasys platform using the privasys MCP tools and CLI. Use when the user wants to ship, run, attest, or manage a confidential-computing workload; manage their Privasys account, team, or billing; or asks how confidential computing, attestation, RA-TLS, the wallet, or data protection work.
---

# Working with Privasys

[Privasys](https://privasys.org) runs apps inside hardware-attested enclaves (Intel SGX/TDX, AMD SEV-SNP), so data stays protected even while it is processed and clients can *verify* what is running. The `privasys` binary is both a CLI and an MCP server (`privasys mcp serve`); prefer the MCP tools when one fits, fall back to the CLI otherwise.

## Answering the user's questions

When the user asks how something works (confidential computing, how Privasys works, RA-TLS, wallet sign-in, how their data is protected), read the matching file in `references/` and answer from it. Do not improvise security specifics; if unsure, say so and point to [docs.privasys.org](https://docs.privasys.org).

- `references/confidential-computing.md` — TEEs, "encrypted in use", what memory encryption alone does not give you.
- `references/how-privasys-works.md` — the platform: enclaves, gateway, attestation, reproducible builds, MCP-per-app.
- `references/ra-tls.md` — how a normal TLS handshake carries hardware proof.
- `references/wallet-auth.md` — sign-in with the wallet or a passkey; the key never leaves the device.
- `references/data-protection.md` — vault-keyed storage, the key is the user's, owner-approved upgrades.

## Onboarding a new user

Account-bearing steps happen **externally** (in the browser); you surface a URL and **poll**, never handling credentials or card details:

1. `auth_status` — check if already signed in.
2. `auth_begin` — start sign-in; show the user the verification URL + code (+ QR). They approve in the Privasys Wallet or with a passkey.
3. `auth_poll` — poll until approved; then you have a session.
4. If the action needs a paid plan or credits, surface the billing portal URL (`billing_portal` / `billing_subscribe`) and poll `billing_status` until active.

The signing key never leaves the wallet; you never see it. Never ask the user to paste a password, token, or card number.

## The core loop

1. `apps_create` — register an app (container image or a GitHub commit; builds are reproducible). For apps that store user data, request encrypted storage (`storage: true`).
2. `apps_store_listing` — set a **description** and **category**. These are required before an app can be deployed, so do this right after creating it.
3. `apps_deploy` (watch to completion) — roll out a version to an enclave.
4. `attest` — challenge the enclave with a fresh nonce and verify its TEE quote. **Do this before trusting the endpoint.**
5. `apps_call` — invoke an app API directly over RA-TLS (the control plane is not in the data path; responses stream).

## Running the user's own backend confidentially

Most users already have a backend (or want to write one). Your job is to make
their container run confidentially — you do **not** rewrite their app. Any
container works if it follows three rules; check/adjust the user's Dockerfile and
app for them:

1. **Listen on `$PORT`.** The platform runs containers on the host network and
   injects a unique `$PORT`; the app must bind it (a hardcoded port fails the
   health probe). Fix code that hardcodes a port to read `$PORT`.
2. **Persist state to `/data`.** `/data` is the per-app encrypted volume (key
   from the vault, reconstructed in the enclave). Point databases/state there
   (e.g. Postgres `PGDATA=/data/pgdata`). Anything elsewhere is ephemeral.
3. **Serve `GET /health` → 200** on `$PORT` (the readiness probe).

Then add a `privasys.json` describing the app's endpoints as tools (so the API
becomes callable as MCP tools over RA-TLS). See the reference app
`container-app-confidential-postgres` for a correct example.

### Protecting the user's IP (private images)

A user who guards their IP keeps their **source private** and builds the image
themselves (their own reproducible build), pushing a **digest-pinned image to a
private registry**. Privasys then runs that image confidentially and attests its
digest — **without ever seeing the source, the image bytes, or the registry
credentials**. The flow:

1. (Human) builds + pushes the private image; gives you the `…@sha256:<digest>`.
2. `apps_create` with the image ref + `storage: true`; `apps_store_listing`.
3. **(Human) registers the pull credential:** ask them to run
   `privasys registry add <app> --token <PAT>` (or `--username/--password`). The
   token goes straight into the vault; only the attested in-enclave manager can
   read it, to pull their image. **Never ask for, accept, echo, or pass the
   registry token yourself** — it is the user's secret, exactly like a password.
4. `apps_deploy` → the in-enclave manager fetches the credential + data key from
   the vault, pulls the private image, and runs it. `attest`, then `apps_call`.

If the user is fine with a public image, skip step 3.

## Securing user data (the data-protection story)

- Encrypted storage is sealed with a **data key that belongs to the user**, generated inside the confidential hardware; the platform never sees it. See `references/data-protection.md`.
- On a new version or enclave upgrade the data is **locked until the owner approves the new measurement**: `apps_versions_pending` then `apps_versions_promote` (or guided `apps upgrade`). The platform cannot approve for them.
- `apps_rotate_key` rotates the key without re-encrypting the data; `apps_cosign` requires a second team approver on promote (separation of duties).
- `apps export-key` lets the owner take their key out. **DANGER:** it writes the key to a *local file only*. Never request, echo, log, or pass the key material anywhere it could reach a model or service. Confirm with the human first.
- `secrets_create` makes a user-owned key in the vault (Shamir-split; the platform never holds it). It generates random material — you never see or handle the secret bytes.
- `secrets_export` writes a secret the owner owns to a **local file only** and returns just a path + fingerprint — never the key. It is **dangerous** (raw key to disk) and requires a fresh WebAuthn step-up the owner approves in their wallet; you cannot approve it. Confirm with the human first.

## The rule that matters

**Attestation is the product.** Before telling a user an endpoint is ready, trustworthy, or safe to send data to, run `attest` and confirm it passed (measurement known, TCB up to date). If attestation fails, say so plainly and treat the endpoint as untrusted. Do not paper over a failed quote.

## Conventions

- Apps are addressable by **name or id** interchangeably.
- Every CLI command supports `--format json`; output auto-switches to JSON when piped. `--no-input` never prompts.
- Exit codes: `0` ok, `3` not authenticated, `4` not authorized, `5` not found.
