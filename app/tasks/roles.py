"""
Celery tasks for role management and upgrades.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import select

from app.celery_app import app
from app.database import AsyncSessionLocal
from app.models import User
from app.rbac import calculate_user_roles
from app.events.event_schemas import UserRoleUpgradedEvent
from app.events.emitter import emit_event


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@app.task(name="app.tasks.roles.process_role_upgrade", bind=True, max_retries=3)
def process_role_upgrade(self, user_id_str: str, target_roles: list[str]):
    """
    Process a delayed role upgrade after 15-minute waiting period.
    
    Double-checks eligibility before applying:
    - trust_score still meets threshold
    - reputation still meets threshold
    - user not blacklisted
    - user not locked
    
    If checks pass: Apply upgrade and emit event
    If checks fail: Cancel upgrade and clear pending_role_upgrade
    
    Args:
        user_id_str: String UUID of the user
        target_roles: List of roles to upgrade to
    """
    import asyncio
    
    async def _process():
        user_id = uuid.UUID(user_id_str)
        
        async with AsyncSessionLocal() as db:
            # Load user
            stmt = select(User).where(User.id == user_id)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            
            if not user:
                # User deleted, nothing to do
                return {"status": "user_not_found", "user_id": user_id_str}
            
            # Check if upgrade is still pending
            if not user.pending_role_upgrade:
                return {"status": "no_pending_upgrade", "user_id": user_id_str}
            
            # Double-check eligibility
            current_roles = calculate_user_roles(user)
            
            # Compare role levels
            role_hierarchy = ["blacklisted", "user", "contributor", "trusted", "curator", "admin"]
            
            def get_max_role_level(roles: list[str]) -> int:
                max_level = 0
                for role in roles:
                    if role in role_hierarchy:
                        max_level = max(max_level, role_hierarchy.index(role))
                return max_level
            
            target_level = get_max_role_level(target_roles)
            current_level = get_max_role_level(current_roles)
            
            if current_level < target_level:
                # Eligibility lost (trust dropped, reputation dropped, blacklisted, locked)
                user.pending_role_upgrade = None
                await db.commit()
                return {
                    "status": "upgrade_cancelled",
                    "user_id": user_id_str,
                    "reason": "Eligibility requirements no longer met",
                    "current_roles": current_roles,
                    "target_roles": target_roles,
                }
            
            # User still eligible - apply upgrade
            old_roles = user.roles or ["user"]
            user.roles = current_roles
            user.pending_role_upgrade = None
            await db.commit()
            await db.refresh(user)
            
            # Emit role upgraded event
            await emit_event(UserRoleUpgradedEvent(
                user_id=user.id,
                old_roles=old_roles,
                new_roles=current_roles,
                trust_score=user.trust_score,
                reputation=user.reputation_percentage,
                reason=user.pending_role_upgrade.get("reason", "Delayed upgrade completed") if user.pending_role_upgrade else "Delayed upgrade completed",
            ))
            
            return {
                "status": "upgrade_applied",
                "user_id": user_id_str,
                "old_roles": old_roles,
                "new_roles": current_roles,
            }
    
    # Run async function
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(_process())
    
    return result
