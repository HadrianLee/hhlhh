import os

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from common import run_migrations
from bff.db.models import Base

try:
    database_url = make_url(os.environ["POSTGRES_BFF_MIGRATOR_URL"])
except KeyError:
    raise RuntimeError("Set POSTGRES_BFF_MIGRATOR_URL before running Alembic") from None
except (ArgumentError, ValueError):
    raise RuntimeError("POSTGRES_BFF_MIGRATOR_URL must be a valid SQLAlchemy database URL") from None

if database_url.drivername != "postgresql+asyncpg":
    raise RuntimeError("POSTGRES_BFF_MIGRATOR_URL must use postgresql+asyncpg")
if not database_url.database or database_url.database in {"postgres", "template0", "template1"}:
    raise RuntimeError("Migrations must target the BFF application database")

run_migrations(
    target_metadata=Base.metadata,
    engine_factory=lambda: create_async_engine(database_url, poolclass=NullPool, hide_parameters=True),
    pre_migration_statements=["SET LOCAL ROLE bff_owner", "CREATE SCHEMA IF NOT EXISTS bff"],
    version_table="alembic_version_bff",
)
