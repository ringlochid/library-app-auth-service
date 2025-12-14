"""
Phase 4: Content Report System Tests

Tests for content reporting, auto-lock, admin review, and unlock functionality.
"""
import pytest
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient
from sqlalchemy import select

from app.main import app
from app.database import get_db
from app.models import User, ContentReport, TrustHistory


class TestReportSubmission:
    """Test report submission by contributors."""
    
    @pytest.mark.asyncio
    async def test_submit_report_as_contributor(
        self, 
        async_client: AsyncClient, 
        contributor_token: str,
        db_session
    ):
        """Contributors can submit reports on edit actions."""
        report = {
            "target": {
                "content_type": "book",
                "content_id": 123,
                "edit_id": 456,
                "action": "update",
                "actor_id": str(uuid.uuid4())
            },
            "reason": "This edit introduced spam links and promotional content.",
            "category": "spam"
        }
        
        response = await async_client.post(
            "/reports",
            json=report,
            headers={"Authorization": f"Bearer {contributor_token}"}
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "pending"
        assert data["category"] == "spam"
        assert data["reason"] == report["reason"]
        assert data["target"]["edit_id"] == 456
    
    @pytest.mark.asyncio
    async def test_submit_report_requires_contributor(
        self, 
        async_client: AsyncClient, 
        user_token: str
    ):
        """Regular users cannot submit reports."""
        report = {
            "target": {
                "content_type": "book",
                "content_id": 123,
                "edit_id": 456,
                "action": "update",
                "actor_id": str(uuid.uuid4())
            },
            "reason": "This edit introduced spam links.",
            "category": "spam"
        }
        
        response = await async_client.post(
            "/reports",
            json=report,
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_submit_report_requires_trust_score(
        self,
        async_client: AsyncClient,
        db_session
    ):
        """Contributors with low trust score cannot submit reports."""
        from app.security import create_access_token
        
        # Create contributor with trust_score < 10
        user = User(
            id=uuid.uuid4(),
            name="lowtrustcontributor",
            email="lowtrustcontributor@example.com",
            hashed_password="fake",
            email_verified_at=datetime.now(timezone.utc),  # Email must be verified
            roles=["user", "contributor"],
            trust_score=5  # Below threshold
        )
        db_session.add(user)
        await db_session.commit()
        
        token, _, _ = create_access_token(
            user.id, 
            is_admin=False, 
            roles=user.roles, 
            trust_score=user.trust_score
        )
        
        report = {
            "target": {
                "content_type": "book",
                "content_id": 123,
                "edit_id": 456,
                "action": "update",
                "actor_id": str(uuid.uuid4())
            },
            "reason": "This edit introduced spam links.",
            "category": "spam"
        }
        
        response = await async_client.post(
            "/reports",
            json=report,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 403
        assert "trust score" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_duplicate_report_prevented(
        self, 
        authenticated_client
    ):
        """Cannot submit duplicate reports on same edit."""
        client, user = authenticated_client
        actor_id = str(uuid.uuid4())
        report = {
            "target": {
                "content_type": "book",
                "content_id": 123,
                "edit_id": 789,
                "action": "delete",
                "actor_id": actor_id
            },
            "reason": "This deletion was malicious and removed valid content.",
            "category": "vandalism"
        }
        
        # First submission succeeds (no auth header needed - user injected via dependency override)
        response1 = await client.post(
            "/reports",
            json=report
        )
        assert response1.status_code == 201
        
        # Second submission fails
        response2 = await client.post(
            "/reports",
            json=report
        )
        assert response2.status_code == 409
        assert "already reported" in response2.json()["detail"].lower()


class TestAutoLock:
    """Test auto-lock mechanism at 10+ trusted reporters."""
    
    @pytest.mark.asyncio
    async def test_auto_lock_at_threshold(
        self, 
        async_client: AsyncClient,
        db_session
    ):
        """User is auto-locked when 10+ distinct trusted reporters report them."""
        from app.security import create_access_token
        
        # Create actor to be reported
        actor = User(
            id=uuid.uuid4(),
            name="badactor",
            email="badactor@example.com",
            hashed_password="fake",
            email_verified_at=datetime.now(timezone.utc),
            roles=["user", "contributor"],
            trust_score=30
        )
        db_session.add(actor)
        
        # Create 10 trusted reporters (trust_score >= 50)
        reporters = []
        for i in range(10):
            reporter = User(
                id=uuid.uuid4(),
                name=f"reporter{i}",
                email=f"reporter{i}@example.com",
                hashed_password="fake",
                email_verified_at=datetime.now(timezone.utc),
                roles=["user", "contributor"],
                trust_score=50 + i
            )
            db_session.add(reporter)
            reporters.append(reporter)
        
        await db_session.commit()
        
        # Submit 10 reports from trusted reporters
        for i, reporter in enumerate(reporters):
            token, _, _ = create_access_token(
                reporter.id, 
                is_admin=False, 
                roles=reporter.roles, 
                trust_score=reporter.trust_score
            )
            report = {
                "target": {
                    "content_type": "book",
                    "content_id": 100,
                    "edit_id": 200 + i,  # Different edit for each
                    "action": "update",
                    "actor_id": str(actor.id)
                },
                "reason": f"This edit #{i} introduced spam content.",
                "category": "spam"
            }
            
            response = await async_client.post(
                "/reports",
                json=report,
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 201
        
        # Verify actor is locked
        await db_session.refresh(actor)
        assert actor.is_locked is True
        assert actor.roles == ["user"]  # Downgraded
    
    @pytest.mark.asyncio
    async def test_auto_lock_ignores_untrusted(
        self, 
        async_client: AsyncClient,
        db_session
    ):
        """Auto-lock only counts reporters with trust_score >= 50."""
        from app.security import create_access_token
        
        actor = User(
            id=uuid.uuid4(),
            name="actor2",
            email="actor2@example.com",
            hashed_password="fake",
            email_verified_at=datetime.now(timezone.utc),
            roles=["user", "contributor"],
            trust_score=30
        )
        db_session.add(actor)
        
        # Create 10 untrusted reporters (trust_score < 50)
        reporters = []
        for i in range(10):
            reporter = User(
                id=uuid.uuid4(),
                name=f"lowreporter{i}",
                email=f"lowreporter{i}@example.com",
                hashed_password="fake",
                email_verified_at=datetime.now(timezone.utc),
                roles=["user", "contributor"],
                trust_score=10 + i  # All below 50
            )
            db_session.add(reporter)
            reporters.append(reporter)
        
        await db_session.commit()
        
        # Submit 10 reports from untrusted reporters
        for i, reporter in enumerate(reporters):
            token, _, _ = create_access_token(
                reporter.id, 
                is_admin=False, 
                roles=reporter.roles, 
                trust_score=reporter.trust_score
            )
            report = {
                "target": {
                    "content_type": "book",
                    "content_id": 101,
                    "edit_id": 300 + i,
                    "action": "update",
                    "actor_id": str(actor.id)
                },
                "reason": f"Report #{i} about spam.",
                "category": "spam"
            }
            
            response = await async_client.post(
                "/reports",
                json=report,
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 201
        
        # Verify actor is NOT locked (untrusted reporters don't count)
        await db_session.refresh(actor)
        assert actor.is_locked is False
    
    @pytest.mark.asyncio
    async def test_auto_lock_ignores_rejected(
        self, 
        authenticated_admin_client
    ):
        """Auto-lock only counts approved/pending reports, not rejected."""
        from app.security import create_access_token
        
        client, admin_user = authenticated_admin_client
        db_session = None
        # Get db session from the app's dependency override
        async for session in app.dependency_overrides[get_db]():
            db_session = session
            break
        
        actor = User(
            id=uuid.uuid4(),
            name="actor3",
            email="actor3@example.com",
            hashed_password="fake",
            email_verified_at=datetime.now(timezone.utc),
            roles=["user", "contributor"],
            trust_score=30
        )
        db_session.add(actor)
        
        # Create 15 trusted reporters
        reporters = []
        for i in range(15):
            reporter = User(
                id=uuid.uuid4(),
                name=f"rejreporter{i}",
                email=f"rejreporter{i}@example.com",
                hashed_password="fake",
                email_verified_at=datetime.now(timezone.utc),
                roles=["user", "contributor"],
                trust_score=60
            )
            db_session.add(reporter)
            reporters.append(reporter)
        
        await db_session.commit()
        
        # Submit 15 reports
        report_ids = []
        for i, reporter in enumerate(reporters):
            token, _, _ = create_access_token(
                reporter.id, 
                is_admin=False, 
                roles=reporter.roles, 
                trust_score=reporter.trust_score
            )
            report = {
                "target": {
                    "content_type": "book",
                    "content_id": 102,
                    "edit_id": 400 + i,
                    "action": "update",
                    "actor_id": str(actor.id)
                },
                "reason": f"Report #{i}.",
                "category": "spam"
            }
            
            response = await client.post(
                "/reports",
                json=report,
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 201
            report_ids.append(response.json()["id"])
        
        # Reject 10 reports as admin (using authenticated admin client, no auth header needed)
        for report_id in report_ids[:10]:
            response = await client.post(
                f"/reports/{report_id}/review",
                json={"action": "reject", "notes": "False report"}
            )
            assert response.status_code == 200
        
        # Verify actor is NOT locked (only 5 pending, need 10+)
        await db_session.refresh(actor)
        assert actor.is_locked is False


class TestAdminReview:
    """Test admin review of reports."""
    
    @pytest.mark.asyncio
    async def test_admin_approve_report(
        self, 
        async_client: AsyncClient,
        contributor_token: str,
        admin_token: str
    ):
        """Admin can approve reports."""
        # Submit report
        actor_id = str(uuid.uuid4())
        report = {
            "target": {
                "content_type": "book",
                "content_id": 200,
                "edit_id": 500,
                "action": "update",
                "actor_id": actor_id
            },
            "reason": "Spam content.",
            "category": "spam"
        }
        
        submit_response = await async_client.post(
            "/reports",
            json=report,
            headers={"Authorization": f"Bearer {contributor_token}"}
        )
        assert submit_response.status_code == 201
        report_id = submit_response.json()["id"]
        
        # Admin approves
        review = {"action": "approve", "notes": "Confirmed spam"}
        review_response = await async_client.post(
            f"/reports/{report_id}/review",
            json=review,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert review_response.status_code == 200
        data = review_response.json()
        assert data["status"] == "approved"
        assert data["review_notes"] == "Confirmed spam"
        assert data["reviewed_by"] is not None
        assert data["reviewed_at"] is not None
    
    @pytest.mark.asyncio
    async def test_admin_reject_report(
        self, 
        async_client: AsyncClient,
        contributor_token: str,
        admin_token: str
    ):
        """Admin can reject reports."""
        actor_id = str(uuid.uuid4())
        report = {
            "target": {
                "content_type": "book",
                "content_id": 201,
                "edit_id": 501,
                "action": "update",
                "actor_id": actor_id
            },
            "reason": "False accusation.",
            "category": "spam"
        }
        
        submit_response = await async_client.post(
            "/reports",
            json=report,
            headers={"Authorization": f"Bearer {contributor_token}"}
        )
        report_id = submit_response.json()["id"]
        
        # Admin rejects
        review = {"action": "reject", "notes": "No evidence of spam"}
        review_response = await async_client.post(
            f"/reports/{report_id}/review",
            json=review,
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert review_response.status_code == 200
        data = review_response.json()
        assert data["status"] == "rejected"
        assert data["review_notes"] == "No evidence of spam"
    
    @pytest.mark.asyncio
    async def test_cannot_review_twice(
        self, 
        authenticated_client,
        authenticated_admin_client
    ):
        """Cannot review already-reviewed reports."""
        contributor_client, contributor_user = authenticated_client
        admin_client, admin_user = authenticated_admin_client
        
        actor_id = str(uuid.uuid4())
        report = {
            "target": {
                "content_type": "book",
                "content_id": 202,
                "edit_id": 502,
                "action": "update",
                "actor_id": actor_id
            },
            "reason": "This is spam content.",
            "category": "spam"
        }
        
        # Submit report as contributor (no auth header needed)
        submit_response = await contributor_client.post(
            "/reports",
            json=report
        )
        assert submit_response.status_code == 201, f"Expected 201, got {submit_response.status_code}: {submit_response.json()}"
        report_id = submit_response.json()["id"]
        
        # First review as admin (no auth header needed)
        review1 = {"action": "approve", "notes": "Confirmed"}
        response1 = await admin_client.post(
            f"/reports/{report_id}/review",
            json=review1
        )
        assert response1.status_code == 200
        
        # Second review fails
        review2 = {"action": "reject", "notes": "Changed mind"}
        response2 = await admin_client.post(
            f"/reports/{report_id}/review",
            json=review2
        )
        assert response2.status_code == 409
        assert "already reviewed" in response2.json()["detail"].lower()


class TestUnlock:
    """Test user unlock functionality."""
    
    @pytest.mark.asyncio
    async def test_admin_unlock_user(
        self, 
        async_client: AsyncClient,
        admin_token: str,
        db_session
    ):
        """Admin can unlock locked users."""
        # Create locked user
        locked_user = User(
            id=uuid.uuid4(),
            name="lockeduser",
            email="lockeduser@example.com",
            hashed_password="fake",
            email_verified_at=datetime.now(timezone.utc),
            roles=["user"],  # Downgraded
            trust_score=50,
            is_locked=True
        )
        db_session.add(locked_user)
        await db_session.commit()
        
        # Unlock
        response = await async_client.post(
            f"/reports/users/{locked_user.id}/unlock",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_locked"] is False
        assert "success" in data["message"].lower()
        
        # Verify roles restored
        await db_session.refresh(locked_user)
        assert locked_user.is_locked is False
        assert "contributor" in locked_user.roles  # Restored (trust_score >= 10)
    
    @pytest.mark.asyncio
    async def test_unlock_creates_audit_trail(
        self, 
        async_client: AsyncClient,
        admin_token: str,
        db_session
    ):
        """Unlocking creates trust history entry."""
        locked_user = User(
            id=uuid.uuid4(),
            name="audituser",
            email="audituser@example.com",
            hashed_password="fake",
            email_verified_at=datetime.now(timezone.utc),
            roles=["user"],
            trust_score=30,
            is_locked=True
        )
        db_session.add(locked_user)
        await db_session.commit()
        
        # Unlock
        await async_client.post(
            f"/reports/users/{locked_user.id}/unlock",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        # Check trust history
        stmt = select(TrustHistory).where(
            TrustHistory.user_id == locked_user.id,
            TrustHistory.reason.contains("Unlocked")
        )
        result = await db_session.execute(stmt)
        history = result.scalar_one_or_none()
        
        assert history is not None
        assert "Unlocked by admin" in history.reason
