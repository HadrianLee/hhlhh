# Browser BFF

The backend for frontend (BFF) owns browser sessions and calls Identity over HTTP.
The browser holds an opaque cookie; BFF holds the access and refresh tokens.
This lets the SPA use a session without reading JWTs in JavaScript.

Identity remains the source of users, passwords, emails, passkeys, MFA, and
identity-local permissions.
Application APIs retain their own permission checks and verify identity JWTs.
The BFF neither imports identity nor connects to its tables.

All commands below run from the repository root.

## Layout

```text
src/bff/
  api/                 cookie/session endpoints and bounded JSON gateways
  core/                configuration, encryption, CSRF, and identity HTTP client
  db/models/           browser_sessions and session_events, schema bff
  db/services/         transactions, row locks, tracking, and retention
  services/            login, refresh, revocation, cleanup, and forwarding
  main.py              FastAPI lifespan, health, readiness, and OpenAPI
```

## Configuration and database

Copy settings from [the environment template](../../../infra/docker/.env.example)
into your deployment configuration and supply your own passwords and secrets.
`BFF_DB_URL` is separate from Identity's `DB_URL`.
Use `postgres:5432` inside the Docker network and `localhost:<published-port>`
when running BFF directly on the host. Hex passwords work unchanged in database
URLs; percent-encode reserved characters in other password formats.

| Required setting | Purpose |
| --- | --- |
| `BFF_DB_URL` | PostgreSQL URL using `postgresql+asyncpg`, the `bff_app` login, and the BFF database |
| `BFF_PUBLIC_ORIGIN` | Exact public HTTPS origin, without a trailing slash |
| `BFF_IDENTITY_BASE_URL` | Reachable Identity origin; Compose sets `http://identity:8000` |
| `BFF_SESSION_HMAC_KEY` | Independent secret of at least 32 bytes for cookie digests and derived CSRF tokens |
| `BFF_TOKEN_ENCRYPTION_KEYS` | Comma-separated Fernet keys for encrypted Identity tokens |

`BFF_UPSTREAMS` optionally maps application names to trusted internal origins.
The [deployment guide](../../../infra/docker/README.md) shows complete local
configuration and secret-generation commands.

Provision a separate `bff` database with the same role separation as identity:

- `bff_owner`: NOLOGIN, owns the database, schema, and tables.
- `bff_app`: LOGIN, CONNECT on `bff`, USAGE on schema `bff`, and
  SELECT/INSERT/UPDATE/DELETE on its tables. No access to identity's tables.
- `bff_migrator`: LOGIN NOINHERIT, CONNECT on `bff`, membership permitting
  `SET ROLE bff_owner`. Only migrations receive this credential.

Terraform grants `bff_app` future object privileges through owner defaults.
The migrator ensures schema `bff` exists as owner. Its version table is
`public.alembic_version_bff`; the application does not need access to it.
Terraform provisions these BFF roles/database and Compose starts BFF behind
Nginx. While the migrator assumes the owner role, it can access data as well as
change schemas. Runtime receives only the app credential.

`BFF_TOKEN_ENCRYPTION_KEYS` contains comma-separated Fernet keys (each is URL-safe
base64 of 32 random bytes). Use `cryptography.fernet.Fernet.generate_key()` in
your secret-generation workflow. Keep the previous encryption key configured
until sessions using it have expired or have refreshed under the new key.
Changing `BFF_SESSION_HMAC_KEY` invalidates existing browser sessions; retain
encryption keys so cleanup can still revoke their identity sessions.

After provisioning, export `POSTGRES_BFF_MIGRATOR_URL` or load your trusted root
`.env` in the shell, then apply the checked-in migrations:

```bash
set -a
source .env
set +a
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini -n bff upgrade head
```

Runtime never calls `create_all` or runs migrations. Identity also needs its own
migration history applied before the full stack starts.

Run the application after exporting its runtime settings:

```bash
uv run --frozen --directory apps/server --package bff bff
```

For a host-run BFF, override `BFF_DB_URL` to use the published PostgreSQL address
and set `BFF_IDENTITY_BASE_URL=http://127.0.0.1:8000`; the root Compose settings
use Docker hostnames that do not resolve from the host shell.

The console script listens on `127.0.0.1:8001`. The Dockerfile follows identity's
locked, non-root multi-stage build and listens on port 8001. Put it behind your
HTTPS reverse proxy, route the frontend and `/api/` through the same origin, and
keep identity/application APIs on the internal network. Cookies always use
Secure, HttpOnly, SameSite=Lax, Path=/, and the `__Host-` prefix; development also
needs HTTPS at the browser boundary. Configure identity's `WEBAUTHN_ORIGIN` to
the public frontend origin and its RP ID to the matching hostname.

When using trusted proxies, explicitly configure Uvicorn's trusted proxy IPs and
the proxy's forwarded-header handling. BFF does not trust caller-supplied
`X-Forwarded-For`. Both BFF and Identity have bounded per-process authentication
rate limits; larger deployments need a shared edge limit. The SPA uses BFF's
login routes; Identity's token endpoints serve backend clients.

## Browser API

Every `/api/` response is `Cache-Control: no-store`. Errors use RFC 9457 problem
details; validation errors do not reflect submitted passwords or tokens.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/auth/csrf` | Fetch an anonymous or current-session CSRF token |
| `POST /api/auth/login` | Authenticate through identity and set the session cookie |
| `POST /api/auth/passkey/options` | Create a discoverable passkey sign-in challenge bound to this browser |
| `POST /api/auth/passkey/login` | Verify the assertion through identity, set the session cookie, and return only `csrf_token` |
| `GET /api/auth/session` | Read current browser-session metadata |
| `GET /api/auth/sessions` | List your browser sessions, including revoked history |
| `GET /api/auth/sessions/{id}/events` | Read your session's lifecycle events |
| `DELETE /api/auth/sessions/{id}` | Revoke one of your browser sessions |
| `POST /api/auth/logout` | End this browser session |
| `POST /api/auth/logout-all` | End all your BFF and identity sessions |
| `POST /api/auth/register` | Forward registration to identity |
| `POST /api/auth/password/forgot` | Request password recovery through identity |
| `POST /api/auth/password/reset` | Complete identity password recovery |
| `POST /api/auth/email/verification/request` | Request identity email verification |
| `POST /api/auth/email/verification/confirm` | Confirm identity email verification |
| `/api/identity/{path}` | Call allowlisted account, challenge, and identity admin routes |
| `/api/apps/{service}/{path}` | Call a configured internal application API |

There is no browser refresh-token endpoint. BFF refreshes tokens under a database
row lock, so multiple requests and replicas cannot rotate the same refresh token
concurrently. Login replaces the current browser cookie with a fresh random
secret and revokes the previous browser session. Identity's public session UUID
is never accepted as a browser credential.

First fetch `/api/auth/csrf`. Send the returned `csrf_token` as `X-CSRF-Token` on
**every POST, PUT, PATCH, and DELETE**, including login and public recovery routes.
The browser's Origin must exactly match `BFF_PUBLIC_ORIGIN`. Login returns a new
CSRF token bound to the new session; replace the token you held before login.
Its response body contains only `{"csrf_token": "..."}`. Fetch
`GET /api/auth/session` separately when you need session metadata.
After logout, fetch `/api/auth/csrf` again. CSRF tokens may be read by JavaScript;
session cookies and identity access/refresh tokens may not.

All API routes share the `csrf_protection` dependency. The apps router also
attaches it directly so enforcement follows the router when mounted separately.
It checks writes; safe GET/HEAD/OPTIONS requests do not require a CSRF token.
Before login, `GET /api/auth/csrf` sets an HttpOnly anonymous CSRF cookie and returns its
derived token without storing server-side CSRF state. With a valid authenticated
session, it recomputes the token from the session secret and sends no Set-Cookie
headers. The token stays reusable while that session secret is unchanged.
Unknown, expired, or revoked session cookies are cleared before issuing anonymous
CSRF protection. Session validity is checked locally. Identity is contacted only
when the access token needs refreshing; a refresh/storage failure returns an error.

```ts
const csrf = await fetch('/api/auth/csrf').then(r => r.json())
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf.csrf_token,
  },
  body: JSON.stringify({ email, password }),
})
if (!response.ok) throw new Error('Sign-in failed')
const login = await response.json()
// Keep login.csrf_token in memory for subsequent writes. No JWT is returned.
const session = await fetch('/api/auth/session').then(r => r.json())
const permissions = await fetch('/api/identity/users/me/permissions')
  .then(r => r.json())
```

Passkey sign-in uses the same cookie and CSRF lifecycle. Fetch options with a
CSRF-protected POST, invoke the browser's WebAuthn API, and post the resulting
assertion. BFF derives the challenge's browser binding from its HttpOnly cookie
secret; this value does not come from JavaScript. A failed sign-in leaves the
current browser session intact. The passkey must already be enrolled in Identity.

For identity, append the original path after `/api/identity/`, for example
`POST /api/identity/challenges/email-otp` or
`POST /api/identity/auth/password/change`. Use identity's existing JSON schemas.
Challenge Location headers are rewritten to the corresponding BFF URL.
Identity still verifies ownership, permissions, passkeys, OTPs, and recent MFA.
Token issuance/refresh and identity session-management paths are excluded from
this gateway. Browser-session endpoints above manage sessions instead.

For example, `BFF_UPSTREAMS='{"example-app":"http://example-app:8000"}'` would map
`/api/apps/example-app/api/items` to `http://example-app:8000/api/items`.
This is an example configuration; the current Compose stack adds no such service.
Upstream origins are administrator configuration, never request parameters.
Authorization is constructed from the stored identity token. Browser cookies,
authorization headers, identity headers, and forwarded headers are not relayed.
Redirects are rejected and upstream Set-Cookie headers are not exposed.
The current gateway supports bounded JSON request/response bodies; file uploads,
streaming, and WebSockets require separately designed endpoints.

OpenAPI is at `/openapi.json`; `/docs` documents cookie authentication and the
required CSRF header. `/health` is process liveness; `/ready` checks session-table
access. Gateway request bodies are documented generically because identity and
each application remain the owners of their request schemas.

## Session lifecycle

Only a keyed digest of the browser cookie is stored. Identity tokens are
encrypted with Fernet and bound to their session/user/token type. The BFF stores
UUID references, device metadata, and lifecycle events; it stores no user profile,
password, permission assignment, passkey, or MFA-verification state.

The default absolute lifetime is 30 days, bounded by identity's refresh expiry.
The default idle lifetime is one day. For an authenticated request:

1. Find the local session by its cookie digest; check revocation, absolute expiry,
   and idle timeout.
2. If the access token is near expiry, refresh it through Identity under the
   session row lock. BFF schedules this from Identity's `expires_in` value.
3. Forward the stored token when the route calls a downstream service. That
   service verifies it using JWKS and checks its own permissions.

Successful password and primary-email changes also revoke that user's local
BFF sessions.

Logout revokes local access immediately. If identity is unavailable, the revoked
session retains encrypted credentials in a retry queue; the cleanup worker retries
identity logout. This queue is never usable for browser authentication. If refresh
results are lost, browser access fails closed rather than reusing a possibly
rotated token. Credentials are erased after remote revocation or refresh expiry.
Revoked sessions and events are retained for 30 days, then purged.

An already-issued JWT remains valid at an application doing only signature/expiry
verification until the JWT expires. Immediate revocation of such tokens requires
additional downstream session validation. BFF observes identity-side revocation
when refresh is rejected, or when a forwarded identity request returns 401. Local
BFF revocation takes effect immediately. Requests already in flight may complete.

Optional positive-integer settings:

| Setting | Default |
| --- | --- |
| `BFF_SESSION_TTL_SECONDS` | `2592000` |
| `BFF_SESSION_IDLE_SECONDS` | `86400` |
| `BFF_REFRESH_MARGIN_SECONDS` | `30` |
| `BFF_CLEANUP_INTERVAL_SECONDS` | `60` |
| `BFF_SESSION_RETENTION_SECONDS` | `2592000` |
| `BFF_MAX_REQUEST_BYTES` | `1048576` |
| `BFF_MAX_RESPONSE_BYTES` | `4194304` |

## Tests

```bash
uv run --frozen --directory apps/server --package bff python -B -m unittest discover -s bff/tests -v
```

The default uses SQLite for portable transaction/API checks. To test PostgreSQL
locking, set `BFF_TEST_DATABASE_URL` to a `postgresql+asyncpg` URL for a disposable
`bff_api_test` database on `localhost` or `127.0.0.1`. The tests drop and recreate
BFF's tables in that database. Never point tests at an application database.
