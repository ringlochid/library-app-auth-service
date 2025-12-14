"""
Phase 5: Session Management Tests

Tests for session listing and tracking.
"""
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from sqlalchemy import select

from app.models import User, RefreshToken


class TestSessionListing:
    """Test GET /auth/sessions endpoint."""
    
    @pytest.mark.asyncio
    async def test_list_sessions_shows_all_active(
        self,
        async_client: AsyncClient,
        db_session,
        contributor_token: tuple[str, User],
    ):
        """List sessions returns all non-revoked, non-expired tokens."""
        access_token, user = contributor_token
        
        # Create multiple refresh tokens (simulating multiple devices)
        family_id_1 = __import__('uuid').uuid4()
        family_id_2 = __import__('uuid').uuid4()
        now = datetime.now(timezone.utc)
        
        rt1 = RefreshToken(
            jti="session1",
            family_id=family_id_1,
            user_id=user.id,
            issued_at=now - timedelta(days=5),
            expires_at=now + timedelta(days=2),
            user_agent="Mozilla/5.0 (Windows NT 10.0)",
            ip_address="192.168.1.100",
            last_used_at=now - timedelta(hours=1),
            last_used_ip="192.168.1.100",
            is_current=True,
        )
        rt2 = RefreshToken(
            jti="session2",
            family_id=family_id_2,
            user_id=user.id,
            issued_at=now - timedelta(days=3),
            expires_at=now + timedelta(days=4),
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone)",
            ip_address="10.0.0.50",
            last_used_at=now - timedelta(minutes=30),
            last_used_ip="10.0.0.55",
            is_current=False,
        )
        db_session.add_all([rt1, rt2])
        await db_session.commit()
        
        # List sessions
        response = await async_client.get(
            "/auth/sessions",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["sessions"]) == 2
        
        # Check sessions are ordered by last_used_at (most recent first)
        assert data["sessions"][0]["user_agent"] == "Mozilla/5.0 (iPhone; CPU iPhone)"
        assert data["sessions"][1]["user_agent"] == "Mozilla/5.0 (Windows NT 10.0)"
    
    @pytest.mark.asyncio
    async def test_list_sessions_excludes_revoked(
        self,
        async_client: AsyncClient,
        db_session,
        contributor_token: tuple[str, User],
    ):
        """Revoked tokens don't appear in session list."""
        access_token, user = contributor_token
        
        family_id = __import__('uuid').uuid4()
        now = datetime.now(timezone.utc)
        
        # Active token
        rt_active = RefreshToken(
            jti="active",
            family_id=family_id,
            user_id=user.id,
            issued_at=now,
            expires_at=now + timedelta(days=7),
            is_current=True,
        )
        
        # Revoked token
        rt_revoked = RefreshToken(
            jti="revoked",
            family_id=family_id,
            user_id=user.id,
            issued_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=6),
            revoked=True,
            is_current=False,
        )
        
        db_session.add_all([rt_active, rt_revoked])
        await db_session.commit()
        
        response = await async_client.get(
            "/auth/sessions",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["sessions"][0]["family_id"] == str(family_id)
    
    @pytest.mark.asyncio
    async def test_list_sessions_excludes_expired(
        self,
        async_client: AsyncClient,
        db_session,
        contributor_token: tuple[str, User],
    ):
        """Expired tokens don't appear in session list."""
        access_token, user = contributor_token
        
        family_id = __import__('uuid').uuid4()
        now = datetime.now(timezone.utc)
        
        # Active token
        rt_active = RefreshToken(
            jti="active",
            family_id=family_id,
            user_id=user.id,
            issued_at=now,
            expires_at=now + timedelta(days=7),
            is_current=True,
        )
        
        # Expired token
        rt_expired = RefreshToken(
            jti="expired",
            family_id=family_id,
            user_id=user.id,
            issued_at=now - timedelta(days=10),
            expires_at=now - timedelta(days=3),  # Expired
            is_current=False,
        )
        
        db_session.add_all([rt_active, rt_expired])
        await db_session.commit()
        
        response = await async_client.get(
            "/auth/sessions",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
    
    @pytest.mark.asyncio
    async def test_list_sessions_shows_current_flag(
        self,
        async_client: AsyncClient,
        db_session,
        contributor_token: tuple[str, User],
    ):
        """Current session has is_current=True."""
        access_token, user = contributor_token
        
        family_id = __import__('uuid').uuid4()
        now = datetime.now(timezone.utc)
        
        rt1 = RefreshToken(
            jti="current",
            family_id=family_id,
            user_id=user.id,
            issued_at=now,
            expires_at=now + timedelta(days=7),
            is_current=True,
        )
        rt2 = RefreshToken(
            jti="old",
            family_id=family_id,
            user_id=user.id,
            issued_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=6),
            is_current=False,
        )
        
        db_session.add_all([rt1, rt2])
        await db_session.commit()
        
        response = await async_client.get(
            "/auth/sessions",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        
        # Find current session
        current = [s for s in data["sessions"] if s["is_current"]][0]
        # SessionItem doesn't expose jti, just verify we found one current session
        assert current["is_current"] is True
    
    @pytest.mark.asyncio
    async def test_list_sessions_requires_auth(
        self,
        async_client: AsyncClient,
    ):
        """Session listing requires authentication."""
        response = await async_client.get("/auth/sessions")
        assert response.status_code == 401


class TestSessionTracking:
    """Test that last_used_at and last_used_ip are updated."""
    
    @pytest.mark.asyncio
    async def test_login_sets_initial_last_used(
        self,
        async_client: AsyncClient,
        db_session,
    ):
        """Login creates token with initial last_used_at and last_used_ip."""
        # Create user
        from app.security import hash_password
        user = User(
            name="tracker",
            email="tracker@example.com",
            hashed_password=hash_password("password123"),
            email_verified_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        await db_session.commit()
        
        # Login
        response = await async_client.post(
            "/auth/login",
            json={"email": "tracker@example.com", "password": "password123"}
        )
        assert response.status_code == 200
        
        # Check refresh token has last_used fields set
        stmt = select(RefreshToken).where(RefreshToken.user_id == user.id)
        result = await db_session.execute(stmt)
        token = result.scalar_one()
        
        assert token.last_used_at is not None
        assert token.last_used_ip is not None
        # last_used_at should equal issued_at on initial login
        assert token.last_used_at == token.issued_at
    
    @pytest.mark.asyncio
    async def test_refresh_updates_last_used(
        self,
        async_client: AsyncClient,
        db_session,
    ):
        """Refreshing token updates last_used_at on old token and sets it on new token."""
        # Create user and login
        from app.security import hash_password
        user = User(
            name="refresher",
            email="refresher@example.com",
            hashed_password=hash_password("password123"),
            email_verified_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        await db_session.commit()
        
        login_response = await async_client.post(
            "/auth/login",
            json={"email": "refresher@example.com", "password": "password123"}
        )
        assert login_response.status_code == 200
        
        # Wait a moment to ensure timestamps differ
        import asyncio
        await asyncio.sleep(0.1)
        
        # Get original token's last_used_at
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_current == True
        )
        result = await db_session.execute(stmt)
        original_token = result.scalar_one()
        original_last_used = original_token.last_used_at
        
        # Refresh token
        refresh_response = await async_client.post("/auth/refresh")
        assert refresh_response.status_code == 200
        
        # Check old token has updated last_used_at
        await db_session.refresh(original_token)
        assert original_token.last_used_at > original_last_used
        assert original_token.is_current == False
        
        # Check new token has last_used_at set
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_current == True
        )
        result = await db_session.execute(stmt)
        new_token = result.scalar_one()
        
        assert new_token.last_used_at is not None
        assert new_token.last_used_at == new_token.issued_at


class TestLogoutAll:
    """Test existing logout with all=true parameter."""
    
    @pytest.mark.asyncio
    async def test_logout_all_revokes_all_sessions(
        self,
        async_client: AsyncClient,
        db_session,
    ):
        """POST /auth/logout?all=true revokes all user sessions."""
        # Create user and login from multiple "devices"
        from app.security import hash_password
        user = User(
            name="multidevice",
            email="multidevice@example.com",
            hashed_password=hash_password("password123"),
            email_verified_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        await db_session.commit()
        
        # Create multiple sessions manually
        family_id_1 = __import__('uuid').uuid4()
        family_id_2 = __import__('uuid').uuid4()
        now = datetime.now(timezone.utc)
        
        rt1 = RefreshToken(
            jti="device1",
            family_id=family_id_1,
            user_id=user.id,
            issued_at=now,
            expires_at=now + timedelta(days=7),
            user_agent="Device 1",
            is_current=True,
        )
        rt2 = RefreshToken(
            jti="device2",
            family_id=family_id_2,
            user_id=user.id,
            issued_at=now,
            expires_at=now + timedelta(days=7),
            user_agent="Device 2",
            is_current=False,
        )
        db_session.add_all([rt1, rt2])
        await db_session.commit()
        
        # Login to get access token
        login_response = await async_client.post(
            "/auth/login",
            json={"email": "multidevice@example.com", "password": "password123"}
        )
        access_token = login_response.json()["access_token"]
        
        # Logout all
        response = await async_client.post(
            "/auth/logout?all=true",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert response.status_code == 204
        
        # Check all tokens are revoked
        stmt = select(RefreshToken).where(RefreshToken.user_id == user.id)
        result = await db_session.execute(stmt)
        tokens = result.scalars().all()
        
        for token in tokens:
            assert token.revoked == True
