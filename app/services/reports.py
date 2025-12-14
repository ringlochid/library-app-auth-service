"""
Content report service functions (Phase 4).
"""
from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.models import ContentReport, User, TrustHistory
from app.rbac import calculate_user_roles


async def check_auto_lock(
    db: AsyncSession,
    actor_id: uuid.UUID,
    *,
    admin_id: uuid.UUID | None = None
) -> bool:
    """
    Check if user should be auto-locked based on approved/pending reports.
    
    Locks user if they have 10+ distinct trusted reporters (trust_score >= 50)
    with reports in 'approved' or 'pending' status.
    
    Args:
        db: Database session
        actor_id: UUID of user being reported
        admin_id: UUID of admin triggering the check (for audit)
    
    Returns:
        True if user was locked, False otherwise
    """
    # Count distinct trusted reporters with approved/pending reports
    stmt = (
        select(func.count(func.distinct(ContentReport.reporter_id)))
        .join(User, User.id == ContentReport.reporter_id)
        .where(
            ContentReport.target["actor_id"].as_string() == str(actor_id),
            ContentReport.status.in_(["pending", "approved"]),
            User.trust_score >= 50  # Trusted reporters only
        )
    )
    result = await db.execute(stmt)
    reporter_count = result.scalar_one()
    
    if reporter_count >= 10:
        # Lock the user
        user = await db.get(User, actor_id)
        if user and not user.is_locked:
            user.is_locked = True
            
            # Create trust history entry for audit
            history = TrustHistory(
                user_id=actor_id,
                delta=0,  # Score unchanged
                old_score=user.trust_score,
                new_score=user.trust_score,
                reason=f"Auto-locked: {reporter_count}+ distinct trusted reporters",
                source="auto_lock",
                created_at=datetime.now(timezone.utc)
            )
            db.add(history)
            
            # Recalculate roles (locked users downgraded to ["user"])
            user.roles = calculate_user_roles(user)
            
            await db.commit()
            return True
    
    return False


async def unlock_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    admin_id: uuid.UUID
) -> None:
    """
    Unlock a user (admin only).
    
    Clears is_locked flag and recalculates roles based on trust score.
    Creates audit trail in trust_history.
    
    Args:
        db: Database session
        user_id: UUID of user to unlock
        admin_id: UUID of admin performing the unlock
    """
    user = await db.get(User, user_id)
    if not user:
        raise ValueError("User not found")
    
    if not user.is_locked:
        return  # Already unlocked
    
    user.is_locked = False
    
    # Create trust history entry for audit
    history = TrustHistory(
        user_id=user_id,
        delta=0,  # Score unchanged
        old_score=user.trust_score,
        new_score=user.trust_score,
        reason="Unlocked by admin",
        source="manual",
        created_at=datetime.now(timezone.utc)
    )
    db.add(history)
    
    # Recalculate roles (restore proper roles based on trust score)
    user.roles = calculate_user_roles(user)
    
    await db.commit()
