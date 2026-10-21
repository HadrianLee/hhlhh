# Run the browser stack

This guide starts the React account UI, BFF, Identity, and PostgreSQL behind one
HTTPS origin. The local Compose overlay adds Mailpit so you can read verification,
reset, and MFA emails without sending real mail.

All commands run in Bash from the repository root. You need Docker Compose with
support for `!override`, uv, Python 3.12+, Terraform 1.11+, and OpenSSL. Node 24 is
used inside the frontend Docker build; it is only needed on the host for direct
frontend checks.

## 1. Configure the local environment

If you already have a working root `.env`, reuse it. For a new checkout, copy the
template and restrict access:

```bash
cp -n infra/docker/.env.example .env
chmod 600 .env
```

The template contains runtime settings. For localhost, complete it with the
following values, replacing every `REPLACE_...` value with an independently
generated secret and the certificate path with your checkout's absolute path:

```dotenv
COMPOSE_FILE=infra/docker/compose.yaml:infra/docker/compose.local.yaml

POSTGRES_ADMIN_USER=postgres_admin
POSTGRES_ADMIN_PASSWORD=REPLACE_ADMIN_PASSWORD
POSTGRES_PORT=5432
POSTGRES_IDENTITY_APP_PASSWORD=REPLACE_IDENTITY_APP_PASSWORD
POSTGRES_IDENTITY_MIGRATOR_PASSWORD=REPLACE_IDENTITY_MIGRATOR_PASSWORD
POSTGRES_BFF_APP_PASSWORD=REPLACE_BFF_APP_PASSWORD
POSTGRES_BFF_MIGRATOR_PASSWORD=REPLACE_BFF_MIGRATOR_PASSWORD

DB_URL=postgresql+asyncpg://identity_app:${POSTGRES_IDENTITY_APP_PASSWORD}@postgres:5432/identity
BFF_DB_URL=postgresql+asyncpg://bff_app:${POSTGRES_BFF_APP_PASSWORD}@postgres:5432/bff
POSTGRES_IDENTITY_MIGRATOR_URL=postgresql+asyncpg://identity_migrator:${POSTGRES_IDENTITY_MIGRATOR_PASSWORD}@localhost:${POSTGRES_PORT}/identity
POSTGRES_BFF_MIGRATOR_URL=postgresql+asyncpg://bff_migrator:${POSTGRES_BFF_MIGRATOR_PASSWORD}@localhost:${POSTGRES_PORT}/bff

TF_VAR_postgres_admin_user=${POSTGRES_ADMIN_USER}
TF_VAR_postgres_admin_password=${POSTGRES_ADMIN_PASSWORD}
TF_VAR_postgres_port=${POSTGRES_PORT}
TF_VAR_postgres_identity_app_password=${POSTGRES_IDENTITY_APP_PASSWORD}
TF_VAR_postgres_identity_migrator_password=${POSTGRES_IDENTITY_MIGRATOR_PASSWORD}
TF_VAR_postgres_bff_app_password=${POSTGRES_BFF_APP_PASSWORD}
TF_VAR_postgres_bff_migrator_password=${POSTGRES_BFF_MIGRATOR_PASSWORD}

DOMAIN=localhost
HTTPS_PORT=443
BFF_PUBLIC_ORIGIN=https://localhost
NGINX_CERTS_DIR=/absolute/path/to/checkout/infra/nginx/certs/localhost
JWT_ISSUER=https://localhost
JWT_AUDIENCE=hhlhh-apps
JWT_ACCESS_TOKEN_TTL_SECONDS=900
JWT_KEY_ROTATION_INTERVAL_SECONDS=3600
IDENTITY_TOKEN_HMAC_KEY=REPLACE_IDENTITY_HMAC_SECRET
BFF_SESSION_HMAC_KEY=REPLACE_BFF_HMAC_SECRET
BFF_TOKEN_ENCRYPTION_KEYS=REPLACE_FERNET_KEY

SMTP_HOST=mailpit
SMTP_PORT=1025
IDENTITY_EMAIL_FROM=identity@example.com
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME='HHLHH Local'
WEBAUTHN_ORIGIN=https://localhost
BFF_UPSTREAMS='{}'
```

Generate a fresh value for each password and HMAC secret:

```bash
# Run once per database password: 16 random bytes become 32 hex characters.
openssl rand -hex 16
# Run once per HMAC secret: 32 random bytes become 64 hex characters.
openssl rand -hex 32
```

Hex values contain no URL-reserved characters. Other password formats may need
percent-encoding in database URLs; the database password itself stays unchanged.
`BFF_TOKEN_ENCRYPTION_KEYS` requires a Fernet key, which has a different format:

```bash
uv sync --frozen --directory apps/server --all-packages
uv run --frozen --directory apps/server --package bff python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Keep the completed `.env` and TLS private key out of Git. Terraform state can
contain sensitive values too. If you have `infra/terraform/terraform.tfvars`,
ensure its admin username and port match `.env`: tfvars values take precedence
over `TF_VAR_...`. Password-version variables in that file must be incremented
when rotating the corresponding write-only application/migrator passwords.

## 2. Prepare HTTPS

Nginx mounts `tls.crt` and `tls.key` from `NGINX_CERTS_DIR`. Reuse your existing
trusted localhost certificate if you have one. Otherwise, create a local
self-signed certificate:

```bash
mkdir -p infra/nginx/certs/localhost
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -keyout infra/nginx/certs/localhost/tls.key \
  -out infra/nginx/certs/localhost/tls.crt \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
sudo chgrp 101 infra/nginx/certs/localhost infra/nginx/certs/localhost/tls.key
chmod 750 infra/nginx/certs/localhost
chmod 640 infra/nginx/certs/localhost/tls.key
chmod 644 infra/nginx/certs/localhost/tls.crt
```

Trust the public `tls.crt` in the browser/OS you use. Nginx runs with UID/GID 101
and needs read access to the mounted files. Keep `tls.key` private. The browser
must trust HTTPS before you test passkeys.

## 3. Start PostgreSQL and provision databases

Check the merged configuration, then start only PostgreSQL:

```bash
docker compose --env-file .env config --quiet
docker compose --env-file .env config --services
docker compose --env-file .env up -d postgres
```

The service list should contain `postgres`, `identity`, `bff`, `nginx`, and
`mailpit`. `COMPOSE_FILE` selects the base file followed by the local overlay, so
the local settings apply last. Explicit `-f` options replace this selection; using
only the base file leaves out Mailpit and the local port override.

Load the environment in the same shell before running Terraform:

```bash
set -a
source .env
set +a
terraform -chdir=infra/terraform init
terraform -chdir=infra/terraform apply
```

Compose reads `.env` for its own configuration. Terraform reads exported
`TF_VAR_...` variables, which is why `source` and `set -a` are needed here.
Only source an environment file you trust.

Terraform connects to the `postgres` maintenance database and creates separate
`identity` and `bff` databases. Application tables go into those databases;
`postgres` holds no application tables.

| Role per service | Purpose |
| --- | --- |
| `*_owner` | Cannot log in; owns the database, schemas, and migration-created objects |
| `*_app` | Connects to its own database and reads/writes application data; cannot assume the owner role |
| `*_migrator` | Connects and explicitly uses `SET LOCAL ROLE *_owner` for schema changes |

Owner default privileges cover new tables, sequences, and routines. While the
migrator assumes the owner role it can access data as well as change schemas.
Application credentials cannot connect to the other service's database or the
maintenance database.

## 4. Apply both migration histories

Keep the exported environment from the previous step, then run:

```bash
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini upgrade head
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini -n bff upgrade head
```

Both services have checked-in initial revisions. These commands apply all pending
table changes, including passkey login. Do not generate a fresh initial revision
or run the historical standalone SQL scripts for a normal installation.
Terraform creates databases and grants; Alembic creates tables. Application
containers do not run migrations. See the [migration guide](../../apps/server/migrations/README.md)
for schema development and revision inspection.

## 5. Start the applications

```bash
docker compose --env-file .env up -d --build
docker compose --env-file .env ps
```

Open **https://localhost** for the SPA and **http://localhost:8025** for Mailpit.
The local overlay starts Mailpit automatically and Identity waits for its image's
health check. Mailpit captures local mail; it does not deliver messages to real
inboxes. Its local storage is temporary.

The startup chain is PostgreSQL health → Identity health → BFF readiness → Nginx.
Nginx serves the built React files and proxies `/api/` to BFF. Vite runs during
the image build; there is no Vite development server in the running Compose
stack. BFF is private; Identity's operator port is loopback-only at
`http://localhost:8000`.

## Rebuilds and troubleshooting

After pulling model changes, apply the migrations first, then rebuild the
affected services. Frontend changes require rebuilding `nginx`:

```bash
docker compose --env-file .env up -d --build identity bff nginx
docker compose --env-file .env logs --tail=100 identity bff nginx
```

| Symptom | Check |
| --- | --- |
| “Use the configured frontend origin” | Open the exact configured origin. `https://localhost`, `https://127.0.0.1`, and a URL with port 5173 are different origins. |
| API request receives HTML | Use Nginx's HTTPS URL. The plain Vite server has no BFF proxy configured. |
| Missing relation/table | Run both Alembic upgrades; container startup does not install schemas. |
| Passkey cannot start | Trust the TLS certificate, enroll a passkey first, and match the public origin and WebAuthn RP configuration. |
| No email | Inspect Mailpit and Identity logs; `SMTP_HOST=mailpit` is a Docker hostname, not a host-shell address. |

Removing the PostgreSQL volume deletes application data. Keep migration files and
Terraform state; recreate the databases with Terraform and replay the migrations.
Changing the image's initial PostgreSQL password environment variable alone does
not rotate a password in an existing volume.

## Deployment beyond localhost

Use an environment file with your real domain, certificate directory, and
reachable SMTP service. Explicitly select the base configuration:

```bash
docker compose --env-file /absolute/path/to/deployment.env -f infra/docker/compose.yaml up -d postgres
```

Provision and migrate using the same steps above with the deployment's exported
credentials, then start the remaining services:

```bash
docker compose --env-file /absolute/path/to/deployment.env -f infra/docker/compose.yaml up -d --build
```

The base file has no Mailpit service. Align `DOMAIN`, `BFF_PUBLIC_ORIGIN`,
`WEBAUTHN_ORIGIN`, and `WEBAUTHN_RP_ID`; origins include a non-default public port.
The current Terraform provider uses `sslmode=disable` for local PostgreSQL, so
its connection configuration needs review before use with a remote database.

Nginx's CSP restricts scripts, styles, and API connections to the same origin,
allows local/data images, and blocks inline scripts/styles and framing. Nginx
overwrites forwarded client headers before BFF receives them. The gateway's
application services must be explicitly listed in `BFF_UPSTREAMS`; each service
still verifies JWTs and enforces its own permissions.
