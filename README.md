# Privasys CLI

The command-line interface to the [Privasys](https://privasys.org) confidential-computing platform. Authenticate with the Privasys Wallet, deploy and manage confidential apps, manage teams and billing, and verify attestation — from a terminal, a CI pipeline, or an AI agent.

Licensed under AGPL-3.0.

## Install

```sh
go install github.com/Privasys/cli/cmd/privasys@latest
```

Pre-built signed binaries (Homebrew, Scoop, direct download) ship with releases. Windows binaries are currently unsigned.

## Authentication

The CLI never holds your signing key. The key stays on your wallet; the CLI holds a short-lived access token it renews silently. Every interactive flow is built on the OAuth 2.0 device authorization grant (RFC 8628).

- **Wallet (default)** — scan the QR with the Privasys Wallet, which verifies enclave attestation before approving:
  ```sh
  privasys auth login
  ```
- **Agent-brokered** — an agent surfaces a verification URL + code to a human, who approves on their wallet/browser, then the agent obtains the token:
  ```sh
  privasys auth begin --agent "My Agent" --format json   # prints verification_uri + user_code
  privasys auth poll --wait                                # completes once approved
  ```
- **No wallet** — open the printed verification URL and use a passkey, security key, or social sign-in.
- **Service account (unattended CI/agents)**:
  ```sh
  privasys auth activate-service-account --key-file ./privasys-sa.json
  # or, zero-touch:
  export PRIVASYS_SERVICE_KEY=/path/to/privasys-sa.json
  ```

Tokens are stored in the OS keychain (with a 0600 file fallback); the long-lived refresh token and service key are kept in the keychain.

## Usage

```sh
privasys config set endpoint https://api.developer.privasys.org
privasys config set account <account-id>

privasys auth whoami
privasys apps list
privasys apps describe <app-id>
```

### Output formats

Every command supports `--format table|json|yaml` (also `PRIVASYS_FORMAT`). Output auto-targets humans by default and machines with `--format json`. Combine with `--no-input` for non-interactive use.

```sh
privasys apps list --format json
TOKEN=$(privasys auth print-access-token)   # pipe into curl, etc.
```

## Configuration & environment

Config lives at `~/.privasys/config.yaml`. Environment overrides: `PRIVASYS_ENDPOINT`, `PRIVASYS_ISSUER`, `PRIVASYS_ACCOUNT`, `PRIVASYS_FORMAT`, `PRIVASYS_SERVICE_KEY`, `PRIVASYS_ACCESS_TOKEN`, `PRIVASYS_NO_INPUT`, `PRIVASYS_CONFIG_DIR`.

## Status

Early development. Implemented: configuration, all four auth modes, `apps list`/`describe`. Planned: full app lifecycle (create/deploy/versions), teams, billing, monitoring, client-side RA-TLS attestation, and an MCP server exposing the full command surface. See the platform CLI plan for the roadmap.
