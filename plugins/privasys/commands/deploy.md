---
description: Deploy a confidential app to Privasys and verify its attestation
argument-hint: "[app name or id]"
---

Deploy and verify a Privasys confidential app. Target: $ARGUMENTS

Use the `privasys` MCP tools (or the `privasys` CLI if a tool is missing):

1. Confirm authentication with `whoami`. If not authenticated, tell the user to run `privasys auth login` (or set `PRIVASYS_SERVICE_KEY` for unattended use) and stop.
2. Resolve the app with `apps_describe` (accepts name or id). If it does not exist and the user clearly intends a new app, create it with `apps_create`.
3. Deploy with `apps_deploy` and watch it to completion.
4. Verify the running enclave with `attest` before reporting success. Never report an endpoint as ready until attestation passes.
5. Summarize: app, version/commit deployed, hostname, and the attestation verdict (measurement + TCB status).
