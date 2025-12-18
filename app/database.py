from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
    AsyncSession,
    AsyncEngine,
)
from sqlalchemy.orm import declarative_base
from app.settings import settings

engine = create_async_engine(str(settings.DATABASE_URL), echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

Base = declarative_base()


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


def create_worker_session() -> tuple[async_sessionmaker[AsyncSession], AsyncEngine]:
    """
    Create a fresh async engine and session factory for Celery worker use.

    This avoids event loop conflicts that occur when reusing the global
    AsyncSessionLocal which is bound to the import-time event loop.

    Returns:
        Tuple of (session_factory, engine) - caller must dispose engine when done.
    """
    # Use worker-specific URL if provided, otherwise fall back to main URL
    db_url = str(settings.DATABASE_WORKER_URL or settings.DATABASE_URL)
    worker_engine = create_async_engine(db_url, echo=False, future=True)
    worker_session = async_sessionmaker(
        worker_engine, expire_on_commit=False, autoflush=False
    )
    return worker_session, worker_engine
