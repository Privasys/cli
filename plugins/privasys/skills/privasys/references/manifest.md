# The app manifest (`privasys.json`)

A container app describes itself in one JSON file, `privasys.json`, at the root
of its repository. The build embeds it in the image as the
`org.privasys.manifest` OCI label, which sits inside the digest-pinned image
config. So the manifest is **measured**: a verifier reads off the image exactly
what the app declares, and changing the manifest changes the image digest the
owner approves.

## Embedding it in the image

The label carries the manifest as compact JSON, base64-encoded (base64 survives
the CSV label parser of `docker buildx`; the platform decodes it):

```yaml
- name: Read privasys.json
  id: manifest
  run: |
    if [ -f privasys.json ]; then
      echo "json=$(jq -c . privasys.json | base64 -w0)" >> "$GITHUB_OUTPUT"
    fi
- uses: docker/build-push-action@v7
  with:
    platforms: linux/amd64
    provenance: false   # an attestation index would change the pinned digest
    sbom: false
    labels: org.privasys.manifest=${{ steps.manifest.outputs.json }}
```

Build single-arch `linux/amd64` with provenance and SBOM off, and deploy the
image **by digest** (`image@sha256:...`). The templates
[`container-app-web`](https://github.com/Privasys/container-app-web) and
[`container-app-example-with-config`](https://github.com/Privasys/container-app-example-with-config)
show the whole workflow.

## Top-level keys

| Key | What it declares |
| --- | --- |
| `tools` | The app's API, one entry per endpoint, in MCP tool format plus Privasys extensions. |
| `configure` | The owner's configuration step (secrets, settings), and whether the app waits for it. |
| `surfaces` | What is served in the clear. Absent means everything is private. |
| `store` | The store listing: `tagline`, `category`, `description`, `keywords`, URLs, support email. |

## Tools

```json
{
  "name": "process",
  "role": "action",
  "description": "Run a short job over a stored dataset.",
  "endpoint": "/actions/process",
  "inputSchema": { "type": "object", "properties": { "dataset": { "type": "string" } }, "required": ["dataset"] },
  "x-privasys": { "auth": "owner" }
}
```

- `role`: `inference` (callable by anyone or agents), `action` (an owner or
  operator operation), `status` (read-only state). The role tells the portal
  and agents what a tool is for; it does not restrict who calls it. That is
  `x-privasys.auth`, below: an `action` that only the owner should run needs
  `"auth": "owner"`.
- `endpoint`: the absolute HTTP path on the container.
- `inputSchema`: JSON Schema. A property can carry
  `"x-privasys": {"secret": true, "label": "API key"}` so the portal and CLI
  mask it, or `"source": {"tool": "datasets", "select": "available"}` for a
  live list of values.
- `x-privasys.progress` on a long-running action names the `status` tool to
  poll and its terminal states.

### Who may call a tool: `x-privasys.auth`

The runtime checks the caller on the tool's endpoint **before the request
reaches the app**, so the app verifies no platform token itself.

| `auth` | Who may call |
| --- | --- |
| `public` (default) | anyone who can reach the route; it still needs a `surfaces.public` entry to be served in the clear |
| `authenticated` | a caller with a verified platform token, or a user in a sealed session |
| `owner` | the app's owner or admin, exactly as on the configure endpoint |
| `role(a, b)` | a verified platform token carrying one of the listed roles, as written |

The endpoint is matched on its canonical path (letter case, slashes, dot
segments, `;parameters` and a trailing format suffix such as `.json` all count
as the same route), for every method. An unknown value refuses the image at
load, and so does a guarded tool whose endpoint is also declared static or
public. Use this rather than writing token checks in the app.

### Charging per call: `x-privasys.price`

```json
"x-privasys": { "auth": "authenticated", "price": { "credits": 5000, "payer": "caller" } }
```

1,000,000 credits = £1. The caller must send `X-Billing-Approved: <credits>
credits` matching the attested price, or gets `402` with `X-Billing-Price`
before any app code runs. The CLI and portal ask for consent and send the
header. A priced route can never be static or public. Changing a price is a
new version.

## The configure section: `configure`

An app that needs secrets or settings from its owner declares a top-level
`configure` section:

```json
"configure": {
  "name": "configure",
  "title": "API credentials",
  "endpoint": "/configure",
  "description": "Inject the API key the app needs before it serves traffic.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "api_key": { "type": "string", "x-privasys": { "secret": true, "label": "API key" } }
    },
    "required": ["api_key"]
  }
}
```

- Only the app's **owner or admin** can call the configure endpoint, however
  the request spells the route, and it can never be public.
- By default the app boots **frozen**: the runtime answers every other request
  with `503` ("awaiting initial configuration") until the app is configured.
  The app validates the payload, stores it under `/data`, and the freeze lifts.
  On restart the app reloads its stored config.
- `"optional": true` means the app has a usable default and serves at once;
  the owner may still configure it. `"readiness_path": "/readiness"` lets the
  app report its own readiness (for slow or async loading) instead of the
  runtime's freeze. Both keep the owner-only check.

Older apps declare a tool with `"role": "config"` or a top-level
`"config_api": {"method": "POST", "path": "/configure"}`; both still work, but
new apps use the `configure` section.

Configure with `apps_configure` (or `privasys apps configure`). Leave secrets
the user wants to keep from you for them to enter themselves.

## Surfaces: what is served in the clear

Everything is **private** unless declared: reached over RA-TLS by attested
clients, or a sealed session by browsers, so nothing between the client and the
enclave reads the traffic. A web app also needs a page that loads before any
session exists, and routes plain HTTPS callers (webhooks, OAuth redirects,
`curl`) can reach. Those are declared, served in the clear through the platform
gateway, and anonymous by construction.

```json
"surfaces": {
  "static": ["/", "/assets/"],
  "public": [
    { "method": "GET",  "path": "/api/v1/public/" },
    { "method": "POST", "path": "/api/v1/webhooks/stripe", "headers": ["Stripe-Signature"] }
  ],
  "cors": "*",
  "limits": { "rps": 10, "burst": 50 }
}
```

- `static`: path prefixes served for GET and HEAD (the browser shell). Exactly
  `"/"` is the root document only. Nothing under `/api` can be static. End a
  directory with `/`.
- `public`: one method per entry. A path ending in `/` is a prefix, any other
  is exact. `headers` lists request headers the route needs beyond the default
  allow-list; `Authorization` and `Cookie` can never be declared.
- `cors`: `"*"` lets public routes answer any origin with no credentials;
  `"same-origin"` (default) sends no cross-origin headers.
- `limits`: per-client rate limit on the clear leg.

On a static or public request the runtime strips `Authorization`, `Cookie` and
every `X-Privasys-*` header, never sets `Set-Cookie`, and stamps
`X-Privasys-Transport: public`. So:

- never serve account data on a public route, and never trust a header there
  (authenticate a webhook by its signature over the body);
- never put a secret in a path or query string;
- call public URLs with `credentials: 'omit'`.

When a version adds a static prefix or public route beyond the set an owner
last confirmed, deploy and stage are refused until the **owner confirms those
routes carry no personal data**. The CLI asks during `apps deploy` and
`apps versions stage` (`--confirm-surfaces` for scripts, or
`apps versions confirm-surfaces <app> [version]`). That confirmation is the
human's, not yours: show them the routes and let them decide.

## Headers the app can trust on private routes

`X-Privasys-Sub` (the signed-in user, asserted by the runtime), the inner
bearer, `X-Privasys-App-*`, and `X-Privasys-Transport` (`sealed`, `attested`,
`direct` or `public`). A private handler refuses `public`.
