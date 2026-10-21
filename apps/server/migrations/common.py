import asyncio
from collections.abc import Callable, Sequence

from alembic import context
from sqlalchemy import Connection, text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.schema import MetaData


def run_migrations(
    *,
    target_metadata: MetaData,
    engine_factory: Callable[[], AsyncEngine],
    pre_migration_statements: Sequence[str] = (),
    version_table: str = "alembic_version",
) -> None:
    schemas = {table.schema for table in target_metadata.tables.values()}

    def include_name(name, type_, parent_names):
        return type_ != "schema" or name in schemas

    def run_online(connection: Connection) -> None:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table=version_table,
            include_schemas=True,
            include_name=include_name,
            compare_type=True,
            transactional_ddl=True,
        )

        with context.begin_transaction():
            for stmt in pre_migration_statements:
                connection.execute(text(stmt))
            context.run_migrations()

    async def run_async() -> None:
        engine = engine_factory()
        try:
            if context.is_offline_mode():
                context.configure(
                    url=engine.url,
                    target_metadata=target_metadata,
                    version_table=version_table,
                    literal_binds=True,
                    dialect_opts={"paramstyle": "named"},
                    transactional_ddl=True,
                )
                with context.begin_transaction():
                    for stmt in pre_migration_statements:
                        context.execute(stmt)
                    context.run_migrations()
            else:
                async with engine.connect() as connection:
                    await connection.run_sync(run_online)
        finally:
            await engine.dispose()

    asyncio.run(run_async())
