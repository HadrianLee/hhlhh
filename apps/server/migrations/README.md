# Database migrations

Terraform creates the PostgreSQL databases, schemas, roles, and grants. Alembic
creates and changes the application tables inside them. Both Identity and BFF
have checked-in revisions, so a fresh installation uses `upgrade head` directly.
Do not generate a new initial revision for deployment.

All commands run from the repository root. Install the locked workspace first:

```bash
uv sync --frozen --directory apps/server --all-packages
```

## Two independent histories

| Service | Alembic selection | URL environment variable | Owner role | Version table |
| --- | --- | --- | --- | --- |
| Identity | Default `[alembic]` | `POSTGRES_IDENTITY_MIGRATOR_URL` | `identity_owner` | `public.alembic_version` |
| BFF | `-n bff` | `POSTGRES_BFF_MIGRATOR_URL` | `bff_owner` | `public.alembic_version_bff` |

URLs must use `postgresql+asyncpg` and the corresponding migrator login, targeting
the application's database. The environments reject maintenance/template
databases. They load model metadata without starting either application and do
not use the runtime `DB_URL` or `BFF_DB_URL`.

For commands running on the host, use `localhost` and the published PostgreSQL
port. Docker application URLs use `postgres:5432` instead. Hex passwords work
unchanged in URLs; percent-encode reserved characters when using other formats.

## Apply existing revisions

After PostgreSQL is running and Terraform has provisioned both databases, export
the migration URLs. If your root `.env` contains them:

```bash
set -a
source .env
set +a
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini upgrade head
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini -n bff upgrade head
```

Each command applies pending revisions in order and records its current revision.
An already current database needs no changes. Containers do not run these
commands for you. See the [deployment guide](../../../infra/docker/README.md)
for the complete first-run sequence.

Each migration transaction executes `SET LOCAL ROLE` for its service's owner.
New objects therefore belong to that owner, and Terraform's default grants give
the app login its intended access. The migrator login is `NOINHERIT`: owner
privileges become active only after explicitly assuming that role. While active,
the owner can also access data; this is not a credential with a strict data-access
ban. The role change ends with the transaction.

## Change a model

Bring a development database to the current revision, edit the model, then
generate a revision for the affected service:

```bash
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini revision --autogenerate -m 'describe identity change'
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini -n bff revision --autogenerate -m 'describe bff change'
```

Run only the applicable command. Review both `upgrade()` and `downgrade()` before
applying and committing the file. Autogeneration compares models to the connected
database; it does not apply changes or reliably infer renames and data migrations.
An empty generated revision means no differences were detected, not that a new
initial schema is needed.

Identity's environments import account, challenge/passkey, and JWKS models across
`identity`, `key_manager`, and `public`. BFF imports its `bff` models. `common.py`
runs the async SQLAlchemy connection through Alembic's synchronous migration API
and limits schema comparisons to those represented in the service's metadata.

## Inspect state and SQL

```bash
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini current
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini history
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini check
```

Add `-n bff` after the configuration path for BFF. `check` detects model/database
differences without writing a revision. To render Identity's SQL without a live
database connection:

```bash
uv run --frozen --directory apps/server --package migrations alembic -c migrations/alembic.ini upgrade head --sql
```

Offline mode still requires a valid configured migration URL. It emits SQL,
including the transaction and owner-role statement, without applying it.

The older files under `sql/` are historical standalone scripts, not Alembic
revisions. A fresh install should use the revision history rather than also
running those scripts. If you delete a local PostgreSQL volume, retain the
revision files and Terraform state, provision the databases again, and replay
both histories with `upgrade head`.
