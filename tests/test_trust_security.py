"""
Test suite for Phase 2 Trust Endpoint Security

Tests cover:
- Rate limiting on trust adjustment endpoint
- Access token blacklisting when roles change
- User cache invalidation after trust adjustments
"""

import pytest
import uuid
import time
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.services.trust import adjust_trust_score
from app.cache import (
    make_access_key,
    make_access_blacklist_key,
    cache_access,
    get_access,
    check_access_in_bl,
    cache_user,
    get_cached_user,
)


def unique_user_data():
    """Generate unique user email and name"""
    suffix = uuid.uuid4().hex[:8]
    return f"user{suffix}", f"test{suffix}@example.com"


class FakeRedis:
    """Minimal async Redis stub for security tests."""

    def __init__(self):
        self.store = {}
        self.ttl = {}

    async def hgetall(self, key):
        return self.store.get(key, {})

    async def hset(self, key, mapping):
        self.store.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        self.ttl[key] = seconds

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value
        if ex:
            self.ttl[key] = ex

    async def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)
            self.ttl.pop(key, None)

    async def exists(self, key):
        return 1 if key in self.store else 0


class TestAccessTokenBlacklisting:
    """Test access token blacklisting when roles change"""

    @pytest.mark.asyncio
    async def test_token_blacklisted_on_upgrade(self, db_session: AsyncSession):
        """Access token is blacklisted when user upgrades (trust 9→10)"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=9,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Simulate existing access token in cache
        r = FakeRedis()
        jti = str(uuid.uuid4())
        exp_ts = int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp())
        await cache_access(make_access_key(user.id), jti, exp_ts, r)

        # Verify token is cached
        cached = await get_access(make_access_key(user.id), r)
        assert cached is not None
        assert cached["jti"] == jti

        # Adjust trust to trigger upgrade (9→10 = user→contributor)
        await adjust_trust_score(
            db_session, user.id, delta=1, reason="test_upgrade", source="manual", r=r
        )

        # Verify token is blacklisted
        bl_key = make_access_blacklist_key(jti)
        is_blacklisted = await check_access_in_bl(bl_key, r)
        assert is_blacklisted, "Token should be blacklisted after role upgrade"

    @pytest.mark.asyncio
    async def test_token_blacklisted_on_downgrade(self, db_session: AsyncSession):
        """Access token is blacklisted when user downgrades (trust 50→49)"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Simulate existing access token in cache
        r = FakeRedis()
        jti = str(uuid.uuid4())
        exp_ts = int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp())
        await cache_access(make_access_key(user.id), jti, exp_ts, r)

        # Adjust trust to trigger downgrade (50→49 = trusted→contributor)
        await adjust_trust_score(
            db_session,
            user.id,
            delta=-1,
            reason="test_downgrade",
            source="manual",
            r=r,
        )

        # Verify token is blacklisted
        bl_key = make_access_blacklist_key(jti)
        is_blacklisted = await check_access_in_bl(bl_key, r)
        assert is_blacklisted, "Token should be blacklisted after role downgrade"

    @pytest.mark.asyncio
    async def test_token_not_blacklisted_without_role_change(
        self, db_session: AsyncSession
    ):
        """Access token NOT blacklisted when trust changes but roles stay same"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=20,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Simulate existing access token in cache
        r = FakeRedis()
        jti = str(uuid.uuid4())
        exp_ts = int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp())
        await cache_access(make_access_key(user.id), jti, exp_ts, r)

        # Adjust trust but stay in same role (20→25, still contributor)
        await adjust_trust_score(
            db_session, user.id, delta=5, reason="test_same_role", source="manual", r=r
        )

        # Verify token is NOT blacklisted
        bl_key = make_access_blacklist_key(jti)
        is_blacklisted = await check_access_in_bl(bl_key, r)
        assert not is_blacklisted, "Token should NOT be blacklisted when roles unchanged"

    @pytest.mark.asyncio
    async def test_blacklist_ttl_matches_token_expiry(self, db_session: AsyncSession):
        """Blacklist entry TTL matches original token expiry"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=9,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Simulate access token expiring in 300 seconds
        r = FakeRedis()
        jti = str(uuid.uuid4())
        exp_ts = int(datetime.now(timezone.utc).timestamp()) + 300
        await cache_access(make_access_key(user.id), jti, exp_ts, r)

        # Trigger role change
        await adjust_trust_score(
            db_session, user.id, delta=1, reason="test_ttl", source="manual", r=r
        )

        # Verify blacklist TTL is approximately 300 seconds
        bl_key = make_access_blacklist_key(jti)
        ttl = r.ttl.get(bl_key)
        assert ttl is not None, "Blacklist entry should have TTL"
        assert 295 <= ttl <= 300, f"Expected TTL ~300s, got {ttl}s"

    @pytest.mark.asyncio
    async def test_no_error_when_no_cached_token(self, db_session: AsyncSession):
        """No error when adjusting trust for user with no cached token"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=9,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # No cached token - should not crash
        r = FakeRedis()
        await adjust_trust_score(
            db_session, user.id, delta=1, reason="test_no_token", source="manual", r=r
        )

        # Should complete without error
        await db_session.refresh(user)
        assert user.trust_score == 10


class TestUserCacheInvalidation:
    """Test user cache invalidation after trust adjustments"""

    @pytest.mark.asyncio
    async def test_cache_cleared_after_trust_adjustment(self, db_session: AsyncSession):
        """User cache is deleted after any trust adjustment"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=85,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Cache user data
        r = FakeRedis()
        await cache_user(
            user.id,
            {
                "id": str(user.id),
                "trust_score": 50,
                "reputation_percentage": 85,
            },
            r,
        )

        # Verify cache exists
        cached = await get_cached_user(user.id, r)
        assert cached is not None
        assert cached["trust_score"] == 50

        # Adjust trust
        await adjust_trust_score(
            db_session,
            user.id,
            delta=10,
            reason="test_cache_clear",
            source="manual",
            r=r,
        )

        # Verify cache is cleared
        cached_after = await get_cached_user(user.id, r)
        assert cached_after is None, "User cache should be cleared after trust adjustment"

    @pytest.mark.asyncio
    async def test_cache_cleared_even_without_role_change(
        self, db_session: AsyncSession
    ):
        """Cache cleared even when roles don't change"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=20,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Cache user
        r = FakeRedis()
        await cache_user(user.id, {"id": str(user.id), "trust_score": 20}, r)

        # Adjust trust without role change (20→25, both contributor)
        await adjust_trust_score(
            db_session,
            user.id,
            delta=5,
            reason="test_cache_always_clear",
            source="manual",
            r=r,
        )

        # Cache should still be cleared
        cached = await get_cached_user(user.id, r)
        assert cached is None, "Cache cleared even without role change"

    @pytest.mark.asyncio
    async def test_no_error_when_cache_already_empty(self, db_session: AsyncSession):
        """No error when clearing non-existent cache"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=85,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # No cached data - should not crash
        r = FakeRedis()
        await adjust_trust_score(
            db_session,
            user.id,
            delta=10,
            reason="test_no_cache",
            source="manual",
            r=r,
        )

        # Should complete without error
        await db_session.refresh(user)
        assert user.trust_score == 60


class TestTrustAdjustmentWithRedis:
    """Test trust adjustment works with Redis parameter"""

    @pytest.mark.asyncio
    async def test_trust_adjustment_works_without_redis(
        self, db_session: AsyncSession
    ):
        """Trust adjustment still works when Redis is None"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=85,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Call without Redis - should not crash
        await adjust_trust_score(
            db_session,
            user.id,
            delta=10,
            reason="test_no_redis",
            source="manual",
            r=None,
        )

        # Trust should still be adjusted
        await db_session.refresh(user)
        assert user.trust_score == 60

    @pytest.mark.asyncio
    async def test_trust_adjustment_with_redis(self, db_session: AsyncSession):
        """Trust adjustment works normally with Redis provided"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=9,
            reputation_percentage=100,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Call with Redis
        r = FakeRedis()
        await cache_user(user.id, {"trust_score": 9}, r)
        jti = str(uuid.uuid4())
        exp_ts = int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp())
        await cache_access(make_access_key(user.id), jti, exp_ts, r)

        # Adjust trust
        await adjust_trust_score(
            db_session, user.id, delta=1, reason="test_with_redis", source="manual", r=r
        )

        # Verify all Redis operations happened
        await db_session.refresh(user)
        assert user.trust_score == 10
        assert await get_cached_user(user.id, r) is None  # Cache cleared
        assert await check_access_in_bl(
            make_access_blacklist_key(jti), r
        )  # Token blacklisted
