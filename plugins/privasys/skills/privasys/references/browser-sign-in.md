# Browser sign-in with the auth SDK

A web page signs people in with Privasys ID, and talks to enclave apps, through the `@privasys/auth` SDK (or the hosted bundle `https://privasys.id/auth/privasys-auth-client.iife.js`, which gives `window.Privasys.AuthFrame`). Read this before writing or reviewing any front-end code that signs people in or calls an enclave app from a browser.

## The rules

- **One `AuthFrame` per page.** Create it once, on first use (a module-level instance), and keep it for the life of the page. Never one per component, per attempt or per enclave app. The SDK warns in the console when two are alive for one client.
- **One client per website.** `clientId` is the website's client. A site that talks to several apps still has one client.
- **The rpId is always `privasys.id`.** There is no option for it. Never derive one from a host: another rpId makes the wallet see a different person.
- **The platform comes from the page's address.** There is nothing to configure.
- **One session per person, client and site.** It is shared by every tab of the site: a sign-in, renewal or sign-out in one tab reaches every tab through `onSessionChange`. It is never shared across sites (browsers partition the frame's storage), by design.
- **Apps are reached with `app(host)` on that one frame.** Never a sign-in per app.

## Decision guide

| The page | Write |
| --- | --- |
| Signs people in only | `new AuthFrame({ clientId, appName })`, `await auth.connect()`, use `session.token` |
| Talks to one enclave app | add `apps: [host]` to the config (the sign-in approves the app in the same tap), then `await auth.app(host)` |
| Talks to several enclave apps | the same frame, `auth.app(host)` per host; list in `apps` the hosts every visit needs |
| Serves wallet users and passkey or external-provider users | `auth.app(host, { audience: 'app:<app id>' })` with `host` the app's own domain in direct mode; set `audience` in the config too |
| Calls an app that takes only direct calls | `auth.app(host, { audience, transport: 'direct' })` |
| Sets up a channel in the background | `auth.app(host, { silent: true })`: rejects with `approval-required[:reason]` instead of notifying the wallet |
| Draws its own sign-in buttons | `headless: { onOptions, onState }` in the config (no passkeys headless) |

## Sealed or direct

`app(host)` picks the channel by how the person signed in:

- **Wallet session: sealed.** End to end from the browser to the attested enclave; the gateway sees only ciphertext. Opened from the wallet's **app approval** for that host: given during the sign-in for the hosts in `apps`, otherwise asked for with one tap (`onApproval(reason)` is called while waiting; `reason` is `null` the first time, or `workload-changed`, `enc-changed`, `voucher-expired` after a change). The host is the app's platform hostname, or a direct domain that serves sealed sessions; never derive it from `location` on a custom domain.
- **Passkey or external sign-in: direct.** HTTPS to `https://<host>` with an access token for `audience` (normally `app:<app id>`, which the client must be registered for). Direct calls are taken on the app's own domain in direct mode, with `"direct": "private"` in the manifest's `surfaces`, not on the platform hostname.

Either way the app reads `X-Privasys-Sub` and never handles a token. `X-Privasys-Transport` says which way a request came; `X-Privasys-Attestation-Level` is `verified` for a wallet user on a direct call.

## The API in one block

```ts
const auth = new AuthFrame({ clientId: 'my-site', appName: 'My Site', apps: ['my-app.apps.privasys.org'] });
auth.onSessionChange((s) => render(s));          // Session | null, from any tab
const session = await auth.connect();            // restore silently or run the gate; ConnectError: cancelled | timeout | failed
const api = await auth.app('my-app.apps.privasys.org');
const res = await api.request('GET', '/api/v1/me');   // { status, headers, body: Uint8Array, transport }
await auth.token('app:<app id>');                // a token for another audience
await auth.renew();                              // roles changed; at most one renewal per 10 s
await auth.signOut();                            // this client, this site, every tab
```

A channel's `state` is `ok`, `reconnecting` (the frame is reopening it from the approval) or `signed-out`. On `signed-out`, call `app(host)` again (after `connect()` if the session ended): the same channel comes back. Never build a new `AuthFrame` to recover.

## Mistakes to flag in review

- `new AuthFrame` inside a component body, an effect, a retry or a per-host helper.
- A second sign-in, a second client, or an `rpId` to reach another app.
- Old API names: `rpId`, `apiBase`, `sessionRelay`, `direct:` in the config, `signIn()`, `getSession()`, `clearSession()`, `getTokenForAudience()`, `ensureAppSession()`, `resumeSession()`, `requestAppVoucher()`, `onSessionRenewed`, `onSessionExpired`, `frame.request()`. Replace them with `connect`, `app`, `token`, `renew`, `signOut`, `onSessionChange`.
- Reading `location.host` as the enclave host on a page served from a custom domain.
- Rebuilding the transport on any 401: a 401 inside a sealed response is the app's own answer.

More: [docs.privasys.org/solutions/privasys-id/sign-in-concepts](https://docs.privasys.org/solutions/privasys-id/sign-in-concepts) and [docs.privasys.org/solutions/privasys-id/auth-sdk](https://docs.privasys.org/solutions/privasys-id/auth-sdk).
