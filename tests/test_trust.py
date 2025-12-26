"""
Test suite for Phase 2 Trust Management System

Tests cover:
- Trust score adjustments
- Reputation calculation (Laplace smoothing)
- Auto-blacklisting at trust ≤ 0
- Delayed role upgrades (15 min countdown)
- Immediate role downgrades
- Locked user role downgrade
- Trust history tracking
"""

import pytest
import uuid
from datetime import datetime, UTC
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, TrustHistory
from app.services.trust import (
    adjust_trust_score,
    recalculate_reputation,
    record_submission_outcome,
    get_trust_history,
)
from app.rbac import calculate_user_roles


def unique_user_data():
    """Generate unique user email and name"""
    suffix = uuid.uuid4().hex[:8]
    return f"user{suffix}", f"test{suffix}@example.com"


class TestTrustScoreAdjustment:
    """Test trust score adjustment logic"""

    @pytest.mark.asyncio
    async def test_positive_adjustment_increases_trust(self, db_session: AsyncSession):
        """Positive delta increases trust score"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=80,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await adjust_trust_score(
            db_session, user.id, delta=10, reason="upload_author", source="upload"
        )

        await db_session.refresh(user)
        assert user.trust_score == 60

    @pytest.mark.asyncio
    async def test_negative_adjustment_decreases_trust(self, db_session: AsyncSession):
        """Negative delta decreases trust score"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=80,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await adjust_trust_score(
            db_session, user.id, delta=-5, reason="upload_rejected", source="upload"
        )

        await db_session.refresh(user)
        assert user.trust_score == 45

    @pytest.mark.asyncio
    async def test_auto_blacklist_at_trust_zero(self, db_session: AsyncSession):
        """User is auto-blacklisted when trust reaches 0 or below"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=5,
            reputation_percentage=80,
            is_blacklisted=False,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await adjust_trust_score(
            db_session, user.id, delta=-10, reason="severe_violation", source="manual"
        )

        await db_session.refresh(user)
        assert user.trust_score <= 0
        assert user.is_blacklisted is True

    @pytest.mark.asyncio
    async def test_trust_history_recorded(self, db_session: AsyncSession):
        """Trust adjustments are recorded in history"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=80,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await adjust_trust_score(
            db_session, user.id, delta=10, reason="upload_book", source="upload"
        )

        result = await db_session.execute(
            select(TrustHistory).where(TrustHistory.user_id == user.id)
        )
        history = result.scalars().all()

        assert len(history) == 1
        assert history[0].delta == 10
        assert history[0].old_score == 50
        assert history[0].new_score == 60
        assert history[0].reason == "upload_book"
        assert history[0].source == "upload"


class TestReputationCalculation:
    """Test reputation calculation with Laplace smoothing"""

    @pytest.mark.asyncio
    async def test_new_user_reputation(self, db_session: AsyncSession):
        """New user (0 submissions) gets baseline reputation"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=0,
            total_submissions=0,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await recalculate_reputation(db_session, user.id)
        await db_session.refresh(user)

        # (3 + 0) / (3 + 0) * 100 = 100%
        assert user.reputation_percentage == 100.0

    @pytest.mark.asyncio
    async def test_perfect_reputation(self, db_session: AsyncSession):
        """User with all successful submissions gets high reputation"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=50,
            total_submissions=50,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await recalculate_reputation(db_session, user.id)
        await db_session.refresh(user)

        # (3 + 50) / (3 + 50) * 100 = 100%
        assert user.reputation_percentage == 100.0

    @pytest.mark.asyncio
    async def test_mixed_reputation(self, db_session: AsyncSession):
        """User with mixed success gets calculated reputation"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=47,
            total_submissions=50,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await recalculate_reputation(db_session, user.id)
        await db_session.refresh(user)

        # (3 + 47) / (3 + 50) * 100 = 94.34%
        expected = (3 + 47) / (3 + 50) * 100
        assert abs(user.reputation_percentage - expected) < 0.01

    @pytest.mark.asyncio
    async def test_poor_reputation(self, db_session: AsyncSession):
        """User with many failures gets low reputation"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=1,
            total_submissions=10,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await recalculate_reputation(db_session, user.id)
        await db_session.refresh(user)

        # (3 + 1) / (3 + 10) * 100 = 30.77%
        expected = (3 + 1) / (3 + 10) * 100
        assert abs(user.reputation_percentage - expected) < 0.01


class TestSubmissionOutcomeTracking:
    """Test submission outcome recording"""

    @pytest.mark.asyncio
    async def test_record_successful_submission(self, db_session: AsyncSession):
        """Successful submission increments both counters"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=5,
            total_submissions=10,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await record_submission_outcome(db_session, user.id, success=True)
        await db_session.refresh(user)

        assert user.successful_submissions == 6
        assert user.total_submissions == 11

    @pytest.mark.asyncio
    async def test_record_failed_submission(self, db_session: AsyncSession):
        """Failed submission increments only total counter"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=5,
            total_submissions=10,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await record_submission_outcome(db_session, user.id, success=False)
        await db_session.refresh(user)

        assert user.successful_submissions == 5  # unchanged
        assert user.total_submissions == 11  # incremented

    @pytest.mark.asyncio
    async def test_reputation_recalculated_after_submission(
        self, db_session: AsyncSession
    ):
        """Reputation is automatically recalculated after recording"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            successful_submissions=0,
            total_submissions=0,
            reputation_percentage=100.0,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        await record_submission_outcome(db_session, user.id, success=False)
        await db_session.refresh(user)

        # (3 + 0) / (3 + 1) * 100 = 75%
        expected = (3 + 0) / (3 + 1) * 100
        assert abs(user.reputation_percentage - expected) < 0.01


class TestDelayedRoleUpgrade:
    """Test delayed role upgrade scheduling"""

    @pytest.mark.asyncio
    @patch("app.tasks.roles.process_role_upgrade.apply_async")
    async def test_upgrade_scheduled_when_eligible(
        self, mock_apply_async: MagicMock, db_session: AsyncSession
    ):
        """Delayed upgrade task is scheduled when user becomes eligible"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=9,  # Just below contributor threshold
            reputation_percentage=80,
            roles=["user"],
            email_verified_at=datetime.now(UTC),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Adjust trust to trigger contributor promotion
        await adjust_trust_score(
            db_session, user.id, delta=1, reason="upload_book", source="upload"
        )

        await db_session.refresh(user)
        # Should schedule upgrade task
        assert mock_apply_async.called
        assert user.pending_role_upgrade is not None
        assert "contributor" in user.pending_role_upgrade.get("target_roles", [])

    @pytest.mark.asyncio
    @patch("app.tasks.roles.process_role_upgrade.apply_async")
    async def test_no_upgrade_if_already_pending(
        self, mock_apply_async: MagicMock, db_session: AsyncSession
    ):
        """No new upgrade task if one is already pending"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=80,
            roles=["user", "contributor"],
            pending_role_upgrade={"roles": ["user", "contributor", "trusted"]},
            email_verified_at=datetime.now(UTC),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Adjust trust but upgrade already pending
        await adjust_trust_score(
            db_session, user.id, delta=5, reason="upload_book", source="upload"
        )

        # Should not schedule new task
        assert not mock_apply_async.called


class TestImmediateRoleDowngrade:
    """Test immediate role downgrade"""

    @pytest.mark.asyncio
    async def test_downgrade_clears_pending_upgrade(self, db_session: AsyncSession):
        """Downgrade clears any pending upgrade"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
            reputation_percentage=80,
            roles=["user", "contributor"],
            pending_role_upgrade={"roles": ["user", "contributor", "trusted"]},
            email_verified_at=datetime.now(UTC),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Negative adjustment that triggers downgrade
        await adjust_trust_score(
            db_session, user.id, delta=-45, reason="violation", source="manual"
        )

        await db_session.refresh(user)
        # Should clear pending upgrade
        assert user.pending_role_upgrade is None
        # Roles should be recalculated immediately
        assert user.roles == ["user"]


class TestLockedUserRoleDowngrade:
    """Test locked users are temporarily downgraded"""

    @pytest.mark.asyncio
    async def test_locked_user_downgraded_to_user(self, db_session: AsyncSession):
        """Locked user with high trust is downgraded to 'user' role"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=80,
            reputation_percentage=90,
            is_locked=True,
            locked_at=datetime.now(UTC),
            email_verified_at=datetime.now(UTC),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        roles = calculate_user_roles(user)

        # Despite high trust/reputation, locked user gets only "user" role
        assert roles == ["user"]

    @pytest.mark.asyncio
    async def test_unlocked_user_regains_roles(self, db_session: AsyncSession):
        """Unlocked user regains roles based on trust/reputation"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=80,
            reputation_percentage=90,
            is_locked=False,
            email_verified_at=datetime.now(UTC),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        roles = calculate_user_roles(user)

        # Should get curator role (trust >= 80, reputation >= 90)
        assert "curator" in roles


class TestTrustHistoryRetrieval:
    """Test trust history pagination"""

    @pytest.mark.asyncio
    async def test_get_paginated_history(self, db_session: AsyncSession):
        """Retrieve paginated trust history"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Create multiple history entries
        for i in range(5):
            await adjust_trust_score(
                db_session,
                user.id,
                delta=1,
                reason=f"action_{i}",
                source="upload",
            )

        # Get first 3 entries
        items, total = await get_trust_history(db_session, user.id, limit=3, offset=0)

        assert total == 5
        assert len(items) == 3
        # Should be ordered by created_at DESC (newest first)
        assert items[0].reason == "action_4"

    @pytest.mark.asyncio
    async def test_history_offset_pagination(self, db_session: AsyncSession):
        """Test offset-based pagination"""
        name, email = unique_user_data()
        user = User(
            name=name,
            email=email,
            hashed_password="fake",
            trust_score=50,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Create 5 history entries
        for i in range(5):
            await adjust_trust_score(
                db_session,
                user.id,
                delta=1,
                reason=f"action_{i}",
                source="upload",
            )

        # Get entries 3-4 (offset=2, limit=2)
        items, total = await get_trust_history(db_session, user.id, limit=2, offset=2)

        assert total == 5
        assert len(items) == 2
        assert items[0].reason == "action_2"
        assert items[1].reason == "action_1"
