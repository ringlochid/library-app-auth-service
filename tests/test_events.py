"""
Test suite for event emission system

Tests cover:
- Event schema validation
- Event emission
- Integration with existing endpoints
"""

import pytest
import json
from datetime import datetime, UTC
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4

from app.events.event_schemas import (
    UserCreatedEvent,
    UserVerifiedEvent,
    UserTrustUpdatedEvent,
    UserRoleUpgradedEvent,
    UserRoleDowngradedEvent,
    UserBlacklistedEvent,
    UserLockedEvent,
)
from app.events.emitter import emit_event, emit_event_dict


class TestEventSchemas:
    """Test event schema validation"""

    def test_user_created_event_schema(self):
        """UserCreatedEvent validates correctly"""
        event = UserCreatedEvent(
            user_id=uuid4(),
            email="test@example.com",
            name="testuser",
            roles=["user"],
            trust_score=0,
        )
        
        assert event.event == "user.created"
        assert event.email == "test@example.com"
        assert event.trust_score == 0
        assert "user" in event.roles

    def test_user_verified_event_schema(self):
        """UserVerifiedEvent validates correctly"""
        user_id = uuid4()
        verified_at = datetime.now(UTC)
        
        event = UserVerifiedEvent(
            user_id=user_id,
            email="test@example.com",
            verified_at=verified_at,
        )
        
        assert event.event == "user.verified"
        assert event.user_id == user_id
        assert event.verified_at == verified_at

    def test_user_trust_updated_event_schema(self):
        """UserTrustUpdatedEvent validates correctly"""
        event = UserTrustUpdatedEvent(
            user_id=uuid4(),
            old_score=10,
            new_score=20,
            delta=10,
            reason="Book approved",
            source="upload",
            pending_upgrade={"target_roles": ["user", "contributor"]},
        )
        
        assert event.event == "user.trust_updated"
        assert event.delta == 10
        assert event.source == "upload"
        assert event.pending_upgrade is not None

    def test_user_role_upgraded_event_schema(self):
        """UserRoleUpgradedEvent validates correctly"""
        event = UserRoleUpgradedEvent(
            user_id=uuid4(),
            old_roles=["user"],
            new_roles=["user", "contributor"],
            trust_score=15,
            reputation=100.0,
            reason="trust_score >= 10",
        )
        
        assert event.event == "user.role_upgraded"
        assert len(event.new_roles) == 2
        assert "contributor" in event.new_roles

    def test_user_role_downgraded_event_schema(self):
        """UserRoleDowngradedEvent validates correctly"""
        event = UserRoleDowngradedEvent(
            user_id=uuid4(),
            old_roles=["user", "contributor"],
            new_roles=["user"],
            trust_score=8,
            reputation=75.0,
            reason="trust_score < 10",
        )
        
        assert event.event == "user.role_downgraded"
        assert len(event.new_roles) == 1
        assert event.trust_score == 8

    def test_user_blacklisted_event_schema(self):
        """UserBlacklistedEvent validates correctly"""
        event = UserBlacklistedEvent(
            user_id=uuid4(),
            trust_score=0,
            reason="Trust score reached 0 (auto-blacklist)",
            automatic=True,
        )
        
        assert event.event == "user.blacklisted"
        assert event.automatic is True
        assert event.trust_score == 0

    def test_user_locked_event_schema(self):
        """UserLockedEvent validates correctly"""
        event = UserLockedEvent(
            user_id=uuid4(),
            report_count=12,
            reason="10+ trusted users reported content",
        )
        
        assert event.event == "user.locked"
        assert event.report_count == 12

    def test_event_json_serialization(self):
        """Events serialize to JSON correctly"""
        event = UserCreatedEvent(
            user_id=uuid4(),
            email="test@example.com",
            name="testuser",
            roles=["user"],
            trust_score=0,
        )
        
        json_str = event.model_dump_json()
        data = json.loads(json_str)
        
        assert data["event"] == "user.created"
        assert data["email"] == "test@example.com"
        assert "timestamp" in data


class TestEventEmitter:
    """Test event emission"""

    @pytest.mark.asyncio
    @patch("app.events.emitter.get_redis")
    async def test_emit_event_publishes_to_redis(self, mock_get_redis):
        """emit_event publishes to Redis channel"""
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock(return_value=1)  # 1 subscriber
        mock_get_redis.return_value = mock_redis
        
        event = UserCreatedEvent(
            user_id=uuid4(),
            email="test@example.com",
            name="testuser",
            roles=["user"],
            trust_score=0,
        )
        
        result = await emit_event(event)
        
        assert result is True
        mock_redis.publish.assert_called_once()
        call_args = mock_redis.publish.call_args
        assert call_args[0][0] == "auth.events"  # channel name

    @pytest.mark.asyncio
    @patch("app.events.emitter.get_redis")
    async def test_emit_event_handles_redis_unavailable(self, mock_get_redis):
        """emit_event handles Redis unavailable gracefully"""
        mock_get_redis.return_value = None
        
        event = UserCreatedEvent(
            user_id=uuid4(),
            email="test@example.com",
            name="testuser",
            roles=["user"],
            trust_score=0,
        )
        
        result = await emit_event(event)
        
        assert result is False  # Should not crash

    @pytest.mark.asyncio
    @patch("app.events.emitter.get_redis")
    async def test_emit_event_dict_publishes_correctly(self, mock_get_redis):
        """emit_event_dict publishes dict payload"""
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock(return_value=1)
        mock_get_redis.return_value = mock_redis
        
        payload = {
            "user_id": str(uuid4()),
            "email": "test@example.com",
            "name": "testuser",
        }
        
        result = await emit_event_dict("user.created", payload)
        
        assert result is True
        mock_redis.publish.assert_called_once()
        call_args = mock_redis.publish.call_args
        published_data = json.loads(call_args[0][1])
        assert published_data["event"] == "user.created"
        assert "timestamp" in published_data

    @pytest.mark.asyncio
    @patch("app.events.emitter.get_redis")
    async def test_emit_event_handles_exceptions(self, mock_get_redis):
        """emit_event handles exceptions gracefully"""
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock(side_effect=Exception("Redis error"))
        mock_get_redis.return_value = mock_redis
        
        event = UserCreatedEvent(
            user_id=uuid4(),
            email="test@example.com",
            name="testuser",
            roles=["user"],
            trust_score=0,
        )
        
        result = await emit_event(event)
        
        assert result is False  # Should not crash, returns False
