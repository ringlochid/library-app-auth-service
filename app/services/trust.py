"""
Trust score management and reputation calculation services.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Literal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User, TrustHistory
from app.rbac import calculate_user_roles
from app.settings import settings


TrustSource = Literal["manual", "upload", "review", "social", "auto_blacklist"]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


async def adjust_trust_score(
    db: AsyncSession,
    user_id: uuid.UUID,
    delta: int,
    reason: str,
    source: TrustSource,
) -> User:
    """
    Adjust user's trust score and handle role changes.
    
    Args:
        db: Database session
        user_id: UUID of the user
        delta: Change in trust score (can be negative)
        reason: Human-readable reason for the adjustment
        source: Source of the adjustment (manual, upload, review, social, auto_blacklist)
        
    Returns:
        Updated User object
        
    Side effects:
        - Creates TrustHistory record
        - Auto-blacklists if trust_score <= 0
        - Schedules delayed role upgrade if eligible
        - Applies immediate downgrade if thresholds lost
    """
    # Load user
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise ValueError(f"User {user_id} not found")
    
    old_score = user.trust_score
    old_roles = calculate_user_roles(user)
    
    # Calculate new score (enforce >= 0 constraint)
    new_score = max(0, old_score + delta)
    
    # Record history
    history_entry = TrustHistory(
        user_id=user_id,
        delta=delta,
        reason=reason,
        source=source,
        old_score=old_score,
        new_score=new_score,
    )
    db.add(history_entry)
    
    # Update user trust score
    user.trust_score = new_score
    
    # Auto-blacklist if trust score hits 0
    if new_score == 0 and not user.is_blacklisted:
        user.is_blacklisted = True
        # Clear any pending upgrades
        user.pending_role_upgrade = None
    
    # Recalculate roles
    new_roles = calculate_user_roles(user)
    
    # Handle role changes
    if new_roles != old_roles:
        # Check if this is an upgrade or downgrade
        role_hierarchy = ["blacklisted", "user", "contributor", "trusted", "curator", "admin"]
        
        def get_max_role_level(roles: list[str]) -> int:
            """Get highest role level from role list."""
            max_level = 0
            for role in roles:
                if role in role_hierarchy:
                    max_level = max(max_level, role_hierarchy.index(role))
            return max_level
        
        old_level = get_max_role_level(old_roles)
        new_level = get_max_role_level(new_roles)
        
        if new_level > old_level and not user.is_blacklisted:
            # UPGRADE: Schedule delayed upgrade (15 minutes)
            from app.tasks.roles import process_role_upgrade
            
            scheduled_at = _now_utc() + timedelta(seconds=settings.ROLE_UPGRADE_DELAY_SECONDS)
            user.pending_role_upgrade = {
                "target_roles": new_roles,
                "scheduled_at": scheduled_at.isoformat(),
                "reason": f"trust_score={new_score}, reputation={user.reputation_percentage}%",
            }
            
            # Schedule Celery task
            process_role_upgrade.apply_async(
                args=[str(user_id), new_roles],
                countdown=settings.ROLE_UPGRADE_DELAY_SECONDS,
            )
        elif new_level < old_level:
            # DOWNGRADE: Apply immediately
            user.pending_role_upgrade = None
            user.roles = new_roles  # Apply new roles immediately
    
    await db.commit()
    await db.refresh(user)
    
    return user


async def recalculate_reputation(db: AsyncSession, user_id: uuid.UUID) -> float:
    """
    Recalculate reputation percentage using Laplace smoothing formula.
    
    Formula: reputation = ((3 + successful) / (3 + total)) * 100
    
    Args:
        db: Database session
        user_id: UUID of the user
        
    Returns:
        New reputation percentage (0-100)
    """
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise ValueError(f"User {user_id} not found")
    
    # Laplace smoothing: prevents harsh penalties for new users
    reputation = ((3 + user.successful_submissions) / (3 + user.total_submissions)) * 100
    
    user.reputation_percentage = round(reputation, 2)
    await db.commit()
    await db.refresh(user)
    
    return user.reputation_percentage


async def record_submission_outcome(
    db: AsyncSession,
    user_id: uuid.UUID,
    success: bool,
) -> float:
    """
    Record a content submission outcome and recalculate reputation.
    
    Args:
        db: Database session
        user_id: UUID of the user
        success: True if submission was approved, False if rejected
        
    Returns:
        New reputation percentage
    """
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise ValueError(f"User {user_id} not found")
    
    # Increment counters
    user.total_submissions += 1
    if success:
        user.successful_submissions += 1
    
    # Recalculate reputation
    reputation = ((3 + user.successful_submissions) / (3 + user.total_submissions)) * 100
    user.reputation_percentage = round(reputation, 2)
    
    await db.commit()
    await db.refresh(user)
    
    return user.reputation_percentage


async def get_trust_history(
    db: AsyncSession,
    user_id: uuid.UUID,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[TrustHistory], int]:
    """
    Retrieve paginated trust history for a user.
    
    Args:
        db: Database session
        user_id: UUID of the user
        limit: Maximum number of records to return
        offset: Number of records to skip
        
    Returns:
        Tuple of (list of TrustHistory records, total count)
    """
    # Get total count
    from sqlalchemy import func
    count_stmt = select(func.count()).select_from(TrustHistory).where(TrustHistory.user_id == user_id)
    count_result = await db.execute(count_stmt)
    total = count_result.scalar_one()
    
    # Get paginated items
    stmt = (
        select(TrustHistory)
        .where(TrustHistory.user_id == user_id)
        .order_by(TrustHistory.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    items = list(result.scalars().all())
    
    return items, total
