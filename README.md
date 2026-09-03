# Privasys CLI

The command-line interface to the [Privasys](https://privasys.org) confidential-computing platform. Authenticate with the Privasys Wallet, deploy and manage confidential apps, manage teams and billing, and verify attestation — from a terminal, a CI pipeline, or an AI agent.

Licensed under AGPL-3.0.

## Install

**Script (macOS / Linux)** — [read it first](https://github.com/Privasys/cli/blob/main/install.sh):
```sh
curl -fsSL https://raw.githubusercontent.com/Privasys/cli/main/install.sh | sh
```

**Homebrew (macOS / Linux):**
```sh
brew install Privasys/tap/privasys
```

**Scoop (Windows):**
```powershell
scoop bucket add privasys https://github.com/Privasys/scoop-bucket
scoop install privasys
```

**Debian / RPM:** download the `.deb` or `.rpm` for your arch from the [releases page](https://github.com/Privasys/cli/releases) and install it with `dpkg -i` / `rpm -i`.

**Binaries:** download the archive for your OS/arch from the [releases page](https://github.com/Privasys/cli/releases) and put `privasys` on your `PATH`. Windows binaries are currently unsigned.

> `go install` is not supported: the CLI links the RA-TLS client library through a `replace` directive. Use the released binaries, or check out `Privasys/ra-tls-clients` next to this repo and run `go build ./cmd/privasys`.

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

Commands that take an app accept either its **id or its name** (e.g. `privasys apps call my-app …`).

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
| `agents` | `init` (wire MCP into Claude Code / Cursor / VS Code / Gemini) |

Deploy an app end to end:
```sh
privasys apps create --name demo --source github --commit-url https://github.com/you/demo/commit/<sha>
privasys apps deploy demo --watch
privasys apps call demo hello --data '{"who":"world"}'
```

> **Data plane is direct.** `apps call` connects to the enclave over RA-TLS, verifies it, and sends the request directly — the control plane is never in the data path. Responses **stream** (chunked and SSE work). By default it verifies the RA-TLS report-data binding locally (fast, no attestation-server round-trip); pass `--attest` for full quote verification against the attestation server. `attest` always does the full check. Control-plane operations (create/deploy/versions, accounts, team, billing) go through the platform API as usual.

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

**One-command wiring.** `privasys agents init` drops the right MCP registration (and an `AGENTS.md` briefing) into your repo so an agent picks up the tools with no manual JSON editing:

```sh
privasys agents init                 # Claude Code + AGENTS.md
privasys agents init --all           # every supported harness (claude, cursor, vscode, gemini)
privasys agents init --print         # show what would be written, touch nothing
```

It is idempotent and never writes secrets — the generated config only points at the local `privasys` binary, which reads its token from the OS keychain.

**Claude Code plugin.** Install the plugin for slash commands (`/deploy`, `/attest`), a workflow skill, and the MCP server in one step:

```sh
claude plugin marketplace add Privasys/cli
claude plugin install privasys@privasys
```

Tools include `whoami`, `apps_list`/`apps_describe`/`apps_create`/`apps_deploy`/`apps_call`/…, `attest`, `attest_direct` (client-side challenge), `verify_quote`, `account_show`, `team_list`/`team_add`, and `billing_*`. The server authenticates exactly like the CLI — a logged-in session, or a service account (`PRIVASYS_SERVICE_KEY`) for unattended use.

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

`privasys attest <app-id>` is **always client-side**: the CLI connects to the app's enclave over RA-TLS (through the gateway's L4 splice), **challenges it with a fresh nonce**, and verifies the quote against the attestation server. You trust the enclave's hardware attestation, not the control plane — there is no server-side proxy path. (`--host` skips even the hostname lookup, so nothing touches the control plane.)

```sh
privasys attest <app-id>                                  # challenge + verify
privasys attest <app-id> --host <app>.apps.privasys.org   # no control-plane lookup at all
privasys attest <app-id> --mrtd <hex>                     # pin an expected measurement
privasys attest <app-id> --extensions                     # print the certificate's OID extensions
privasys attest <app-id> --out ./att                      # dump certificate.pem, quote.bin, attestation.json
privasys attest <app-id> --format json                    # full result as JSON
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
