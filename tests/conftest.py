"""
Pytest configuration to ensure the project root is on sys.path.
"""
import sys
from pathlib import Path

# Add project root to path BEFORE any app imports
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

from app.models import Base, User
from app.settings import settings
from app.main import app
from app.security import create_access_token, get_current_user_with_access_token
from app.database import get_db
from app.redis_client import get_redis


class FakeRedis:
    """
    Fake Redis client for testing to avoid event loop issues.
    Implements the Redis interface used by the app without actual connections.
    """
    def __init__(self):
        self.kv_store = {}
        self.hash_store = {}

    async def hgetall(self, key):
        return self.hash_store.get(key, {})

    async def hset(self, key, mapping):
        self.hash_store.setdefault(key, {}).update({k: str(v) for k, v in mapping.items()})

    async def expire(self, key, seconds):
        return True

    async def set(self, key, value, ex=None):
        self.kv_store[key] = value

    async def get(self, key):
        return self.kv_store.get(key)

    async def delete(self, key):
        self.kv_store.pop(key, None)

    async def exists(self, key):
        return 1 if key in self.kv_store else 0

    def pipeline(self):
        return _FakePipeline(self)


class _FakePipeline:
    """Fake Redis pipeline for testing."""
    def __init__(self, redis_client: FakeRedis):
        self.redis = redis_client
        self.ops = []

    def get(self, key):
        self.ops.append(("get", key))
        return self

    def delete(self, key):
        self.ops.append(("delete", key))
        return self

    async def execute(self):
        results = []
        for op, key in self.ops:
            if op == "get":
                results.append(await self.redis.get(key))
            elif op == "delete":
                await self.redis.delete(key)
                results.append(1)
        return results


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


@pytest_asyncio.fixture
async def async_client(db_session):
    """Create an async HTTP client for testing with fake Redis."""
    async def override_get_db():
        yield db_session
    
    # Create fresh FakeRedis for each test to avoid event loop issues
    fake_redis = FakeRedis()
    
    async def override_get_redis():
        return fake_redis
    
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def user_token(db_session):
    """Create a regular user and return their access token."""
    from datetime import datetime, timezone
    user = User(
        id=uuid.uuid4(),
        name="testuser",
        email="testuser@example.com",
        hashed_password="fake",
        roles=["user"],
        trust_score=0,
        email_verified_at=datetime.now(timezone.utc)
    )
    db_session.add(user)
    await db_session.commit()
    
    token, _, _ = create_access_token(
        user_id=user.id,
        is_admin=False,
        roles=user.roles,
        trust_score=user.trust_score,
        reputation_percentage=user.reputation_percentage
    )
    return token


@pytest_asyncio.fixture
async def contributor_token(db_session):
    """Create a contributor user and return their access token."""
    from datetime import datetime, timezone
    user = User(
        id=uuid.uuid4(),
        name="contributor",
        email="contributor@example.com",
        hashed_password="fake",
        roles=["user", "contributor"],
        trust_score=15,
        email_verified_at=datetime.now(timezone.utc)
    )
    db_session.add(user)
    await db_session.commit()
    
    token, _, _ = create_access_token(
        user_id=user.id,
        is_admin=False,
        roles=user.roles,
        trust_score=user.trust_score,
        reputation_percentage=user.reputation_percentage
    )
    return token


@pytest_asyncio.fixture
async def admin_token(db_session):
    """Create an admin user and return their access token."""
    from datetime import datetime, timezone
    user = User(
        id=uuid.uuid4(),
        name="admin",
        email="admin@example.com",
        hashed_password="fake",
        roles=["user", "admin"],
        trust_score=100,
        is_admin=True,
        email_verified_at=datetime.now(timezone.utc)
    )
    db_session.add(user)
    await db_session.commit()
    
    token, _, _ = create_access_token(
        user_id=user.id,
        is_admin=True,
        roles=user.roles,
        trust_score=user.trust_score,
        reputation_percentage=user.reputation_percentage
    )
    return token


# Alternative fixtures that bypass JWT validation (like test_avatar_endpoints.py)
@pytest_asyncio.fixture
async def authenticated_client(db_session):
    """
    Create an async HTTP client with a mock user injected directly.
    This bypasses JWT token validation entirely, following the pattern from test_avatar_endpoints.py.
    Use this for tests that make multiple requests with the same user to avoid token/Redis issues.
    """
    from datetime import datetime, timezone
    
    # Create user in database
    user = User(
        id=uuid.uuid4(),
        name="contributor",
        email="contributor@example.com",
        hashed_password="fake",
        roles=["user", "contributor"],
        trust_score=15,
        email_verified_at=datetime.now(timezone.utc)
    )
    db_session.add(user)
    await db_session.commit()
    
    # Define override that returns the user directly
    async def fake_current_user():
        return user
    
    async def override_get_db():
        yield db_session
    
    fake_redis = FakeRedis()
    
    async def override_get_redis():
        return fake_redis
    
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis
    app.dependency_overrides[get_current_user_with_access_token] = fake_current_user
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client, user
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authenticated_admin_client(db_session):
    """
    Create an async HTTP client with a mock admin user injected directly.
    This bypasses JWT token validation entirely.
    """
    from datetime import datetime, timezone
    
    # Create admin user in database
    user = User(
        id=uuid.uuid4(),
        name="admin",
        email="admin@example.com",
        hashed_password="fake",
        roles=["user", "admin"],
        trust_score=100,
        is_admin=True,
        email_verified_at=datetime.now(timezone.utc)
    )
    db_session.add(user)
    await db_session.commit()
    
    # Define override that returns the user directly
    async def fake_current_user():
        return user
    
    async def override_get_db():
        yield db_session
    
    fake_redis = FakeRedis()
    
    async def override_get_redis():
        return fake_redis
    
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis
    app.dependency_overrides[get_current_user_with_access_token] = fake_current_user
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client, user
    
    app.dependency_overrides.clear()
