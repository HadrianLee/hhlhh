# Account SPA

The React, TypeScript, and React Router frontend calls BFF at `/api/` on the same
HTTPS origin. BFF handles cookie sessions and token refresh; Identity owns user
data and enforces account-security rules. All commands run from the repository
root.

## Pages

| Page | Behavior |
| --- | --- |
| `/login` | Password or discoverable-passkey sign-in, then fetch the browser session and user separately |
| `/register` | Create an account and request verification |
| `/verify-email#token=...` | Public email-link destination with a single Verify button; the token stays hidden |
| `/forgot-password` | Request password reset instructions with a generic acknowledgment |
| `/reset-password#token=...` | Reset a password using the email token |
| `/mfa` | Signed-in security-code or passkey check for a pending sensitive change |
| `/settings/profile` | Read account details and update the username |
| `/settings/emails` | Verify the primary email; add, verify, remove, and promote secondary addresses |
| `/settings/security` | Passkey verification, passkey enrollment, and password changes |
| `/settings/sessions` | Paginated sessions and activity; revoke a session or sign out everywhere |
| `/settings/access` | Read the current user's Identity permissions |

The UI covers account features without administration pages. Passkeys support
sign-in, enrollment, and signed-in MFA. There is no passkey list/delete API, so
those controls are not offered. Password changes, email changes, and
enrollment require a recent challenge; Identity remains the authority for that
check. Password and primary-email changes revoke sessions and return to login.
New passwords need at least eight characters, without composition rules. The
same rule applies in React, Identity and OpenAPI; login accepts long passwords
through BFF as well. Registration asks users to check their inbox for a verification link.
Email MFA uses a shared code form with Verify code and Resend code buttons.

To use **Sign in with passkey**, first enroll a passkey in Security settings.
Sign-in does not require entering an email address: the browser lets the user
choose a discoverable credential. Identity verifies user presence/verification,
the signature, RP ID, origin, user handle, and signature counter. Login challenges
expire after five minutes, allow five attempts, are bound to the requesting
browser, and can only be used once. Successful passkey sign-in also establishes
recent MFA in the new identity session. BFF returns only a new CSRF token and
sets its usual HttpOnly session cookie; JWTs remain in BFF.

## Sensitive changes

Submitting a sensitive change checks Identity's current MFA status first. With
recent MFA, the change runs immediately. Otherwise the SPA opens `/mfa` and
requests an email challenge automatically. A correct code or passkey resumes the
pending change once and returns to its settings page. This covers adding,
removing and promoting email addresses, password changes, and passkey enrollment.
Identity still checks MFA inside its mutation routes and database transactions.

Pending actions and their form values stay in memory, bound to the current user
and browser session. They are discarded on cancellation, leaving the MFA page,
session changes, or reload. Passwords and pending request bodies are never placed
in browser history, URLs, localStorage or sessionStorage. A network error never
causes an automatic replay. An explicit MFA-expiry rejection can start the
verification flow again. If the resumed change fails, its error appears back on
the settings page.

## Session and CSRF behavior

The browser automatically sends the BFF's HttpOnly session cookie. React never
reads it or stores JWTs. The shared API client fetches `/api/auth/csrf` before a
write and keeps the returned token in memory. Login replaces it with the
session-derived token returned by BFF. Every POST, PATCH and DELETE sends
`X-CSRF-Token`; the browser supplies `Origin`. Reloads obtain a CSRF token
from the current session. Failed writes are never automatically replayed.

Email links put their secret in a URL fragment rather than a query parameter.
The SPA reads and removes it before mounting React, then waits for explicit
confirmation. Tokens are sent only in the request body. Do not reload the page
before confirmation; the removed token is deliberately not persisted. Reopen
the email link if needed. Verification tokens retain their complete `primary.`
or secondary-email prefix. Only MFA uses six-digit codes.
Verification links work while signed out. The app provides no navigation link or
button to the verification page; users open it from their email. Password reset
also remains public.
Both email-link pages read their token from the fragment without displaying a
token field. Missing links show instructions and disable submission.

## Code map

| Location | Responsibility |
| --- | --- |
| `src/pages/` | Public authentication pages, MFA handoff, and settings |
| `src/components/AccountProvider.tsx` | Current browser session and account state |
| `src/components/MfaProvider.tsx` | Keep a pending sensitive action in memory and resume it once |
| `src/components/EmailOtpForm.tsx` | Shared six-digit code and resend form |
| `src/lib/api.ts` | Same-origin fetch, in-memory CSRF, and safe API errors |
| `src/lib/passkeys.ts` | Browser WebAuthn ceremonies |
| `src/lib/link-token.ts` | Capture and remove email-link fragments |
| `tests/` | Authentication helper tests |

## Running

Follow the [deployment guide](../../infra/docker/README.md) to provision the
databases, apply both migration histories, and configure HTTPS. Then rebuild the
services from the repository root:

```bash
docker compose --env-file .env up -d --build identity bff nginx
```

Open `https://localhost`. The local TLS certificate must be trusted for browser
passkeys. Keep `BFF_PUBLIC_ORIGIN`, `WEBAUTHN_ORIGIN` and the actual public origin
aligned. Identity uses `BFF_PUBLIC_ORIGIN` to construct email links.
Nginx's build stage uses Vite to produce `dist`; its final image serves static
files and proxies `/api/` to BFF. No Vite development server runs in Compose.
`npm --prefix apps/web run dev` alone has no API proxy and does not provide the
configured HTTPS origin or session-cookie flow. Use the Compose URL for the
documented local account workflow.

## Checks

Use Node 24, matching the Nginx build stage. These commands run from the
repository root without changing directories:

```bash
npm --prefix apps/web ci
npm --prefix apps/web run build
npm --prefix apps/web run lint
npm --prefix apps/web test
```

The build checks TypeScript and bundles the SPA. Linting uses the existing oxlint
configuration; Node's test runner checks authentication helpers. These checks do
not replace browser testing of cookies, mail links, and the native passkey prompt.
