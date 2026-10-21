# Server workspace

This uv workspace contains two FastAPI services and their shared Python packages.
All commands below run from the repository root; `--directory apps/server`
selects this workspace without changing your terminal's working directory.

## Responsibilities

| Package | Responsibility | Details |
| --- | --- | --- |
| `identity` | Own users, credentials, email addresses, passkeys, and Identity-local permissions; issue JWTs | [Identity](identity/README.md) |
| `bff` | Authenticate browser cookies, refresh tokens, track sessions, and forward API calls | [BFF](bff/README.md) |
| `migrations` | Version Identity and BFF tables with separate Alembic histories | [Migrations](migrations/README.md) |
| `auth-token` | Verify JWTs against a configured public JWKS | [JWT verification](lib/auth-token/README.md) |
| `authz-helper` | Reuse SQLAlchemy role, permission, and audit model columns | [Authorization helpers](lib/authz-helper/README.md) |
| `email-delivery` | Send a common message contract through SMTP or Resend | [Email delivery](lib/email-delivery/README.md) |

Identity answers who the user is. Each application decides what that user may do
with its own data. BFF connects the browser to those services without returning
JWTs to frontend JavaScript or reading Identity's tables directly.

## Install and start

Use Python 3.12+ and uv. Docker images use Python 3.13. Install the locked
workspace dependencies:

```bash
uv sync --frozen --directory apps/server --all-packages
```

For the full browser flow, use the [Docker setup](../../infra/docker/README.md).
It explains the required order: PostgreSQL, Terraform, both Alembic upgrades,
then the applications. Application startup never creates tables.

To run a service directly after exporting its runtime settings and migrating its
database:

```bash
uv run --frozen --directory apps/server --package identity uvicorn identity.main:app --host 127.0.0.1 --port 8000
```

```bash
uv run --frozen --directory apps/server --package bff bff
```

For host-run services, database URLs must use `localhost` and the published
PostgreSQL port; BFF's Identity URL must use `http://127.0.0.1:8000`. The Compose
environment uses Docker service names instead. BFF still needs an HTTPS browser
entry point because its cookies are Secure. The Identity ASGI entry point above
starts the API; the current `identity` console script is a placeholder.

## Code structure

Both services separate HTTP handling from application logic and persistence:

```text
api/          routes, dependencies, request/response schemas, and status codes
services/     account/session use cases and service coordination
db/models/   SQLAlchemy tables and constraints
db/services/ transactions, queries, and row locking
core/         security, configuration, and shared application infrastructure
main.py       lifespan initialization and FastAPI application
```

This keeps a route focused on its HTTP contract while database services enforce
state changes inside transactions. Services share small library contracts rather
than importing each other's application models.

## Checks

Run these from the repository root. `uv run --directory` executes each Python
command inside `apps/server`, so test paths are relative to that directory.

```bash
uv run --frozen --directory apps/server --package identity python -B -m unittest discover -s identity/tests -v
uv run --frozen --directory apps/server --package bff python -B -m unittest discover -s bff/tests -v
uv run --frozen --directory apps/server --package auth-token python -B -m unittest discover -s lib/auth-token/tests -v
uv run --frozen --directory apps/server --package email-delivery python -B -m unittest discover -s lib/email-delivery/tests -v
```

Identity and BFF use SQLite by default. PostgreSQL-only locking tests are skipped
unless `IDENTITY_TEST_DATABASE_URL` or `BFF_TEST_DATABASE_URL` points to the
corresponding disposable local test database. These tests recreate tables; follow
the safeguards in each service README. Email transport tests mock external I/O.

For frontend checks, see the [web guide](../web/README.md#checks).
