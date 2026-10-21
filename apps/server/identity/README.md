# Identity API

Identity owns users, credentials, email addresses, passkeys, and authentication
proofs. It issues short-lived RS256 JWTs identifying a user (`sub`) and login
session (`sid`). Each application checks its own permissions; Identity's roles
and permissions apply to Identity's administration routes only.

The React SPA calls Identity through BFF. BFF holds the JWTs and presents its own
cookie session to the browser. The bearer-token routes documented here are the
service API; see [BFF](../bff/README.md) for browser-facing paths.

## Setup and configuration

All commands run from the repository root. Follow the [deployment guide](../../../infra/docker/README.md)
to start PostgreSQL, provision databases with Terraform, and apply the checked-in
Identity and BFF Alembic revisions before starting the stack. Do not also apply
historical files from `migrations/sql/` to a fresh Alembic-managed database.

For running Identity directly, export these settings before importing the app:

```dotenv
DB_URL=postgresql+asyncpg://identity_app:PASSWORD@localhost:5432/identity
JWT_ISSUER=https://localhost
JWT_AUDIENCE=hhlhh-apps
JWKS_URL=http://127.0.0.1:8000/.well-known/jwks.json
JWT_ACCESS_TOKEN_TTL_SECONDS=900
JWT_KEY_ROTATION_INTERVAL_SECONDS=3600
IDENTITY_TOKEN_HMAC_KEY=REPLACE_WITH_AN_INDEPENDENT_RANDOM_SECRET
SMTP_HOST=localhost
SMTP_PORT=1025
IDENTITY_EMAIL_FROM=identity@example.com
BFF_PUBLIC_ORIGIN=https://localhost
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=Identity
WEBAUTHN_ORIGIN=https://localhost
```

`DB_URL` must use the application login, not the owner or migrator. Inside
Compose, database and SMTP hosts are `postgres` and `mailpit`; the local overlay
exposes Mailpit's inbox on port 8025, not its SMTP port. A host-run Identity needs
an SMTP server reachable from the host.

The token HMAC secret must contain at least 32 bytes and be shared across Identity
instances. Changing it invalidates existing refresh tokens. Optional settings:

| Variable | Default, seconds |
| --- | ---: |
| `IDENTITY_REFRESH_TOKEN_TTL_SECONDS` | 2592000 |
| `IDENTITY_VERIFICATION_TOKEN_TTL_SECONDS` | 3600 |
| `IDENTITY_PASSWORD_RESET_TOKEN_TTL_SECONDS` | 1800 |
| `JWT_CLOCK_SKEW_SECONDS` | 5 |

Install and run the ASGI application after exporting its settings:

```bash
uv sync --frozen --directory apps/server --all-packages
uv run --frozen --directory apps/server --package identity uvicorn identity.main:app --host 127.0.0.1 --port 8000
```

`/health` checks process liveness. `/docs` and `/openapi.json` describe the API.
The public `GET /.well-known/jwks.json` exposes public RSA signing keys from
`key_manager.jwks`. The JWT profile uses RFC 7517 JWK fields (`kty`, `kid`, `use`,
`alg`, `n`, `e`) with typed columns and database constraints. Private signing keys
are not included in JWKS. Startup creates an active signing key and schedules
rotation; previous public keys remain available for their validity window.

## Account routes

These paths include the `/api` prefix. Protected routes require
`Authorization: Bearer ACCESS_TOKEN` and an active, unbanned user/session.

| Method | Path | Behavior |
| --- | --- | --- |
| POST | `/api/auth/register` | Register and schedule a verification email |
| POST | `/api/auth/login` | Return access/refresh tokens, session ID, and expiry |
| POST | `/api/auth/passkey/options` | Create a browser-bound discoverable passkey login challenge |
| POST | `/api/auth/passkey/login` | Verify the assertion and create a session with recent MFA |
| POST | `/api/auth/refresh` | Rotate the refresh token; reuse revokes its session |
| POST | `/api/auth/logout` | Revoke the current session |
| POST | `/api/auth/logout-all` | Revoke all of the current user's sessions |
| GET | `/api/auth/sessions` | List the user's Identity sessions |
| DELETE | `/api/auth/sessions/{session_id}` | Revoke an owned session |
| POST | `/api/auth/password/change` | Require recent MFA; change password and revoke sessions |
| POST | `/api/auth/password/forgot` | Request recovery with a generic acknowledgment |
| POST | `/api/auth/password/reset` | Consume a reset token and revoke sessions |
| POST | `/api/auth/email/verification/request` | Request primary-email verification |
| POST | `/api/auth/email/verification/confirm` | Consume a primary/secondary verification token; public access |
| GET, PATCH | `/api/users/me` | Read profile or update username |
| GET | `/api/users/me/permissions` | Read Identity-local permissions for UI rendering |
| GET, POST | `/api/users/me/emails` | List secondary emails; adding one requires recent MFA |
| DELETE | `/api/users/me/emails/{email_id}` | Remove an owned secondary email with recent MFA |
| POST | `/api/users/me/emails/{email_id}/verification` | Send an owned email's verification link |
| POST | `/api/users/me/emails/{email_id}/primary` | Promote a verified email with recent MFA; revoke sessions |

New passwords require **at least eight characters**, with no composition rules.
Whitespace and Unicode are accepted without trimming or normalization. The shared
`NewPassword` type covers registration, changes, and resets. Login verifies
self-describing scrypt hashes. Refresh tokens are integrity-protected; Identity
stores their HMAC-SHA256 digests rather than their raw values.

Protected endpoints use the shared [auth-token](../lib/auth-token/README.md)
JWKS verifier, then query Identity's current user/session and local permissions.
An external service verifying JWTs offline accepts an already-issued token until
expiry unless it adds a live session check. A permission returned to React is
useful for rendering; it does not replace the server's permission check.

## Email links and codes

Lifespan creates `IdentityMailDelivery` using `SmtpMailService` from
[email-delivery](../lib/email-delivery/README.md) and installs it as
`app.state.identity_email_delivery`. Missing or blank `SMTP_HOST`, `SMTP_PORT`,
`IDENTITY_EMAIL_FROM`, or `BFF_PUBLIC_ORIGIN` raises `RuntimeError`. Invalid ports,
sender addresses, or public origins also prevent startup. Construction does not
connect to SMTP or send mail.

Identity loads its HTML templates from `templates/email/` for each delivery and
renders them with `string.Template`. Dynamic values are HTML-escaped. Verification
and reset links use the configured HTTPS frontend origin, never request headers:

- `/verify-email#token=...` opens the public verification page.
- `/reset-password#token=...` opens password recovery.
- MFA emails display a six-digit code; they do not use these link tokens.

The SPA removes the fragment before mounting React and waits for the user to
confirm before posting the token. Emails show action links without raw token
blocks or manual-paste instructions. The full `primary.` or secondary-email UUID
prefix is retained inside the hidden token so Identity can identify its purpose.
Verification/reset tokens are single-use; a new request replaces the previous
one of that type. Requests are limited to one per account/type per minute.

Verification/reset delivery runs as an in-process background task after the HTTP
response. Failures are logged without exposing secrets or account existence;
there is no durable delivery queue. MFA delivery is awaited: failure returns 503
and cancels the challenge. The default SMTP adapter currently uses the configured
host/port without authentication or TLS, matching local Mailpit. The shared
transport library also supports authenticated SMTP and Resend, but Identity's
startup currently selects local-style SMTP.

Tests may replace the delivery hook after startup and before requests:

```python
async def capture_email(*, email: str, purpose: str, token: str) -> None:
    # Capture synthetic test messages here; do not log real secrets.
    ...

async with app.router.lifespan_context(app):
    app.state.identity_email_delivery = capture_email
    # Make requests with the test client here.
```

The callable accepts `verify_account`, `password_reset`, or `mfa_email_otp`.
`IdentityMailDelivery.send_otp(email=..., code="000123")` validates six ASCII
digits and preserves leading zeroes. Startup still validates SMTP configuration
before a test replacement; shutdown removes the installed hook.

## Recent MFA and passkeys

A recent proof belongs to an active Identity session and lasts five minutes.
Password changes, secondary-email additions/removals/promotions, passkey
enrollment, and administration writes require it. The SPA can pause a form,
complete a challenge, then resume the action; Identity rechecks the proof inside
its mutation transaction.

| Method | Path | Behavior |
| --- | --- | --- |
| POST | `/api/challenges/email-otp` | Send a code to the verified primary email |
| POST | `/api/challenges/passkey-registration` | Require recent MFA; return creation options for a discoverable credential |
| POST | `/api/challenges/passkey-authentication` | Return request options for the signed-in user's passkeys |
| GET | `/api/challenges/mfa` | Read the current session's recent proof and expiry |
| GET | `/api/challenges/{challenge_id}` | Read a challenge owned by the user and session |
| POST | `/api/challenges/{challenge_id}/verify` | Complete an OTP or WebAuthn ceremony once |

Challenge creation returns 201, `Location`, purpose, status, expiry, and attempts
remaining. Passkey responses also include WebAuthn JSON `public_key` options.
The browser converts those with `PublicKeyCredential.parseCreationOptionsFromJSON`
or `parseRequestOptionsFromJSON`, invokes `navigator.credentials.create/get`, and
submits the credential's `toJSON()` value. Verification bodies use a method tag:

```json
{"method": "email_otp", "code": "012345"}
```

```json
{"method": "passkey_authentication", "credential": {"id": "...", "rawId": "...", "type": "public-key", "response": {"clientDataJSON": "...", "authenticatorData": "...", "signature": "...", "userHandle": "..."}}}
```

Registration uses `passkey_registration` with an `attestationObject` response.
The library `webauthn` generates challenges and verifies challenge, RP ID, origin,
user presence/verification, saved public keys, and signature counters. Cross-origin
iframe ceremonies are rejected. Store only public credential keys. The first
passkey also requires recent MFA: verify the primary email, complete an email
code challenge, then enroll. Enrollment alone does not create a new MFA proof.

Email OTPs use `secrets.randbelow`, expire in five minutes, allow five attempts,
and have a 60-second resend delay across the user's sessions. Only a
purpose-separated HMAC digest is stored, bound to challenge, user, session, and
recipient. A replacement challenge cancels its pending predecessor for the same
purpose/session.

Passkey **sign-in** uses the separate public `/api/auth/passkey/*` routes and
`identity.passkey_login_challenges`, because no user session exists yet. BFF
supplies a browser binding derived from its HttpOnly cookie secret. Identity
returns discoverable options without asking for an email address, then verifies
the credential and its user handle. The challenge expires in five minutes, allows
five attempts, and is consumed atomically with session creation and counter
updates. Successful sign-in establishes recent MFA for the new session.

For a protected password change, complete an email/passkey authentication
challenge in the same session, then send:

```json
{"new_password": "a new password with at least eight characters"}
```

A missing or expired recent proof returns 403. Password confirmation is not
accepted as authorization for these changes. Password and primary-email changes
revoke all sessions; logout and owned-session revocation remain available without
an MFA challenge. Account recovery uses its single-use emailed reset token.

## Identity administration

Public registration never grants administrative access. A trusted operator can
bootstrap an existing active account, with `DB_URL` set to the correct Identity
database:

```bash
uv run --frozen --directory apps/server --package identity python -m identity.bootstrap_admin --user-id USER_UUID
```

The command is idempotent, creates audit records, and assigns a protected system
role. The API checks permissions on every administration request:

| Permission | Route family, under `/api` |
| --- | --- |
| `identity.users.read` | Users, their sessions, roles, and permissions |
| `identity.users.manage` | Bans and revoking another user's sessions |
| `identity.roles.read` | Role definitions and attached permissions |
| `identity.roles.manage` | Role definitions, user assignments, and role-permission links |
| `identity.permissions.read` | Permission definitions |
| `identity.permissions.manage` | Create/change/delete permission definitions |
| `identity.audit.read` | Role-assignment, role-definition, and role-permission audit logs |

Administration writes also require recent MFA; a proof does not grant permissions.
Lists accept `limit` (1–100, default 50) and nonnegative `offset`. Audit snapshots
remain readable after role/permission deletion. System roles and their permission
identifiers are protected. See OpenAPI for the complete endpoint/schema contract.

## HTTP behavior and tests

Account/challenge responses are `no-store`. Errors use RFC 9457
`application/problem+json`; authentication errors include `WWW-Authenticate`,
and throttling includes `Retry-After`. Signed-in challenge expiry returns 410,
completion/replacement 409, and an invalid answer 400. Anonymous passkey login
failures use a generic 401. Authentication endpoints are limited to 30 requests
per client IP per minute per process; multiple workers need a shared edge limit.

Run the tests from the repository root:

```bash
uv run --frozen --directory apps/server --package identity python -B -m unittest discover -s identity/tests -v
```

Tests use SQLAlchemy session scopes over a SQLite test driver by default. Set
`IDENTITY_TEST_DATABASE_URL` to a disposable `postgresql+asyncpg` database named
`identity_api_test` on `127.0.0.1` or `localhost` to enable PostgreSQL concurrency
tests for refresh, reset, and passkey completion. Tests recreate model tables;
never use an application database. Email hooks use synthetic test messages.
