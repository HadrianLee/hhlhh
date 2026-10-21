from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


def create_session_factory(database_url: str):
    engine = create_async_engine(database_url, pool_pre_ping=True, hide_parameters=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
