from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


engine = None
async_session_factory = None


def init_engine(database_url: str):
    global engine, async_session_factory
    engine = create_async_engine(database_url, echo=False, pool_size=10, max_overflow=20)
    async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session():
    async with async_session_factory() as session:
        yield session


async def close_engine():
    global engine
    if engine:
        await engine.dispose()
