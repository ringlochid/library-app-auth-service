"""
Pytest configuration to ensure the project root is on sys.path.
"""
import sys
from pathlib import Path
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

from app.models import Base
from app.settings import settings

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """
    Create a test database session for each test.
    Uses the same DATABASE_URL as configured in settings.
    """
    test_engine = create_async_engine(
        str(settings.DATABASE_URL), 
        future=True, 
        poolclass=NullPool
    )
    
    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create session
    TestSessionLocal = async_sessionmaker(
        test_engine, 
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with TestSessionLocal() as session:
        yield session
    
    # Cleanup
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await test_engine.dispose()
