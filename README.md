# Privasys CLI

The command-line interface to the [Privasys](https://privasys.org) confidential-computing platform. Authenticate with the Privasys Wallet, deploy and manage confidential apps, manage teams and billing, and verify attestation — from a terminal, a CI pipeline, or an AI agent.

Licensed under AGPL-3.0.

## Install

**Script (macOS / Linux):**
```sh
curl -fsSL https://privasys.org/cli/install.sh | sh
```

**Go:**
```sh
go install github.com/Privasys/cli/cmd/privasys@latest
```

**Binaries:** download a signed archive for your OS/arch from the [releases page](https://github.com/Privasys/cli/releases) and put `privasys` on your `PATH`. Windows binaries are currently unsigned.

Verify:
```sh
privasys version
```

Shell completions:
```sh
privasys completion bash|zsh|fish|powershell
```

## Quickstart

```sh
privasys auth login                 # scan the QR with your Privasys Wallet
privasys apps list
privasys apps describe <app-id>
privasys attest <app-id> --verify
```

## Authentication

The CLI never holds your signing key — it stays on your wallet. The CLI holds a short-lived access token it renews silently. Every interactive flow is the OAuth 2.0 device authorization grant (RFC 8628).

| Mode | Command | Use it for |
| --- | --- | --- |
| **Wallet (default)** | `privasys auth login` | A human with the Privasys Wallet — scan the QR; the wallet verifies enclave attestation before approving. |
| **Agent-brokered** | `privasys auth begin --agent "<name>"` then `privasys auth poll --wait` | An agent surfaces the verification URL + code to a human, who approves; the agent then gets the token. |
| **No wallet** | open the URL printed by `auth login` | Complete a passkey, security key, or social sign-in in the browser. |
| **Service account** | `privasys auth activate-service-account --key-file key.json` | Unattended CI / agents (no human). Or set `PRIVASYS_SERVICE_KEY`. |

Helpers: `privasys auth whoami`, `auth print-access-token`, `auth list`, `auth logout`.

Tokens are stored in the OS keychain (with a `0600` file fallback); the long-lived refresh token and service key live in the keychain.

## Commands

| Group | Commands |
| --- | --- |
| `apps` | `list`, `describe`, `create`, `upload`, `delete`, `versions {list,create}`, `deploy [--watch]`, `deployments`, `stop`, `api`, `mcp`, `call`, `builds`, `owners {list,add,remove}` |
| `account` | `show`, `update` |
| `team` | `list`, `add`, `set-role`, `remove` |
| `billing` | `balance`, `usage`, `ledger`, `status`, `subscribe`, `buy-credits`, `portal` |
| `attest` | `attest <app-id>` (see [Attestation](#attestation)) |
| `auth` | `login`, `begin`, `poll`, `activate-service-account`, `whoami`, `print-access-token`, `list`, `logout` |
| `config` | `set`, `get`, `list` |
| `mcp` | `serve` (see [For AI agents](#for-ai-agents)) |

Deploy an app end to end:
```sh
privasys apps create --name demo --source github --commit-url https://github.com/you/demo/commit/<sha>
privasys apps deploy demo --watch
privasys apps call demo hello --data '{"who":"world"}'
```

Manage a team and billing:
```sh
privasys team add <sub> --email dev@acme.com --role member
privasys apps owners add demo <sub>
privasys billing balance
privasys billing subscribe          # opens Stripe Checkout (no card data touches the CLI)
```

## For AI agents

The CLI is built to be driven by AI agents.

**MCP server.** `privasys mcp serve` exposes the full command surface as [Model Context Protocol](https://modelcontextprotocol.io) tools over stdio. Register it with an MCP client:

```jsonc
// MCP client config (e.g. Claude Desktop)
{
  "mcpServers": {
    "privasys": { "command": "privasys", "args": ["mcp", "serve"] }
  }
}
```

```sh
# Claude Code
claude mcp add privasys -- privasys mcp serve
```

Tools include `whoami`, `apps_list`/`apps_describe`/`apps_create`/`apps_deploy`/`apps_call`/…, `attest`, `verify_quote`, `account_show`, `team_list`/`team_add`, and `billing_*`. The server authenticates exactly like the CLI — a logged-in session, or a service account (`PRIVASYS_SERVICE_KEY`) for unattended use.

**Scripting.** Every command takes `--format json` (and `yaml`); output auto-switches to JSON when stdout is not a TTY. `--no-input` never prompts. Stable exit codes:

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | generic error |
| `3` | not authenticated |
| `4` | not authorized |
| `5` | not found |

```sh
TOKEN=$(privasys auth print-access-token)        # pipe into curl
privasys apps list --format json | jq '.[].name'
```

## Attestation

`privasys attest <app-id>` fetches the deployed app's RA-TLS attestation (TEE quote, measurements, certificate, and Privasys OID extensions) and can verify and export it.

```sh
privasys attest <app-id>                       # summary: quote type, MRENCLAVE/MRTD, RTMRs
privasys attest <app-id> --challenge $(openssl rand -hex 16)   # fresh challenge-response quote
privasys attest <app-id> --extensions          # print the certificate's OID extensions
privasys attest <app-id> --verify              # verify the quote with the attestation server
privasys attest <app-id> --out ./att           # dump all artifacts to a directory
privasys attest <app-id> --format json         # full attestation as JSON
```

`--out <dir>` writes:

| File | Contents |
| --- | --- |
| `attestation.json` | the full attestation result |
| `certificate.pem` | the RA-TLS leaf certificate (x509 PEM) |
| `app-certificate.pem` | the per-workload certificate, when present |
| `quote.bin` | the raw TEE quote bytes |
| `extensions.json` | the Privasys OID extensions (`oid`, `label`, `value_hex`) |
| `verify.json` | the attestation-server verdict (with `--verify`) |

## Configuration & environment

Config lives at `~/.privasys/config.yaml` (named configurations). Global flags: `--endpoint`, `--issuer`, `--account`, `--format`, `--no-input`, `--quiet`.

```sh
privasys config set endpoint https://api.developer.privasys.org
privasys config set account <account-id>
privasys config list
```

| Env var | Purpose |
| --- | --- |
| `PRIVASYS_ENDPOINT` | platform API base URL |
| `PRIVASYS_ISSUER` | identity provider issuer URL |
| `PRIVASYS_ACCOUNT` | account to act on |
| `PRIVASYS_FORMAT` | default output format |
| `PRIVASYS_SERVICE_KEY` | service-account key (path or inline JSON) for unattended auth |
| `PRIVASYS_ACCESS_TOKEN` | inject a pre-minted access token |
| `PRIVASYS_NO_INPUT` | never prompt |
| `PRIVASYS_CONFIG_DIR` | override the config directory |
