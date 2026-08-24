"""
Async Database Setup and Session Management

WHY THIS FILE EXISTS:
    The entire application is async (FastAPI + aiohttp collectors).
    A synchronous database engine would block the event loop on every query.
    This file provides an async SQLAlchemy engine and session factory.

WHAT IT DOES:
    - Creates an ``AsyncEngine`` (using aiosqlite for dev, swap to
      asyncpg for PostgreSQL in production via DATABASE_URL)
    - Provides ``AsyncSessionLocal`` session factory
    - Provides ``get_db()`` dependency for FastAPI routes
    - Provides ``init_db()`` / ``close_db()`` lifecycle hooks

HOW OTHER FILES USE IT:
    - Routes:     ``db = Depends(get_db)``
    - Repository: accepts ``AsyncSession`` as parameter
    - app.py:     calls ``init_db()`` on startup, ``close_db()`` on shutdown
"""
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def get_db():
    """FastAPI dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables.  Called once on application startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose of the engine connection pool on shutdown."""
    await engine.dispose()
