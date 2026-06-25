# Authentication with the Privasys Wallet

Privasys signs you in through **privasys.id** (the identity provider) using your
phone as the authenticator, or a standard passkey. The private key that proves
who you are **never leaves your device**; servers only ever see short-lived
tokens.

## How the CLI / an agent signs you in

The CLI uses the OAuth 2.0 **Device Authorization Grant** (RFC 8628), the same
flow smart TVs use:

1. `auth_begin` (or `privasys auth login`) asks privasys.id to start a device
   authorization and gets back a **verification URL** + a short **user code** (and
   a wallet QR).
2. You approve on your phone (Privasys Wallet) or in the browser with a passkey or
   social login. The wallet verifies the request and authenticates you with a
   hardware-backed key (FIDO2/WebAuthn) gated by your biometric.
3. The CLI polls (`auth_poll`) and receives a short-lived access token plus a
   refresh token. It renews silently; you do not sign in again each time.

An agent never handles your credentials: it shows you the URL/code and **polls**
until you have approved externally.

## Why this is strong

- **The key stays on the device.** Authentication is a hardware-backed FIDO2
  signature; there is no password to phish and no secret on the server to steal.
- **Phishing-resistant.** WebAuthn binds the signature to the origin.
- **Wallet attestation.** Before approving, the wallet can verify the enclave it
  is signing into is genuine (attestation) — so you are not approving a request to
  an impostor.

## Wallet or your own passkey

You do not have to use the Privasys Wallet. Any standard FIDO2 passkey or security
key works (good for enterprises that standardise on their own authenticators). The
strength comes from the properties (hardware-bound key, your presence, phishing
resistance), not from the wallet brand specifically.

## Unattended (CI / agents with no human)

Set `PRIVASYS_SERVICE_KEY` to a service-account key for headless use. No device
flow, no human approval; use it only where a human cannot approve.

More: [docs.privasys.org/solutions/privasys-id/overview](https://docs.privasys.org/solutions/privasys-id/overview).
