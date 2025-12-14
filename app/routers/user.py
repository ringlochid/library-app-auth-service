from datetime import datetime, timezone, timedelta
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from redis.asyncio import Redis

from app.database import get_db
from app.redis_client import get_redis
from app.cache import token_bucket_allow, make_rate_limit_key
from app.settings import settings
from app.models import User, TrustHistory
from app.security import get_current_user_with_access_token
from app.dependencies.service_auth import verify_service_token
from app.schemas.trust import (
    TrustAdjustRequest,
    TrustResponse,
    TrustHistoryResponse,
    TrustHistoryItem,
)
from app.services.trust import adjust_trust_score, get_trust_history
from app.rbac import calculate_user_roles

router = APIRouter(prefix='/user', tags=["user services"])


@router.post("/admin/users/{user_id}/trust/adjust", response_model=TrustResponse)
async def adjust_user_trust(
    user_id: uuid.UUID,
    payload: TrustAdjustRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
    _service_auth: None = Depends(verify_service_token),
):
    """
    Adjust a user's trust score (admin/service only).
    
    This endpoint is used by Library Service to adjust trust scores based on:
    - Content submission outcomes (book/author approved/rejected)
    - Review helpfulness ratings
    - Social engagement (follows, subscriptions)
    
    Role changes (upgrades) are delayed by 15 minutes with double-check.
    Downgrades are applied immediately.
    Auto-blacklist occurs at trust_score = 0.
    
    Requires: X-Service-Token header or admin authentication
    Rate limited: 10 calls per hour per user_id
    """
    # Rate limit by target user_id (prevents spamming same user)
    allowed, remaining = await token_bucket_allow(
        make_rate_limit_key("trust_adjust", str(user_id)),
        capacity=settings.RATE_LIMIT_TRUST_ADJUST_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_TRUST_ADJUST_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_TRUST_ADJUST_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for user {user_id}. Try again later."
        )
    
    try:
        user = await adjust_trust_score(
            user_id=user_id,
            delta=payload.delta,
            reason=payload.reason,
            source=payload.source,
            db=db,
            r=r,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
    return TrustResponse(
        user_id=user.id,
        trust_score=user.trust_score,
        reputation_percentage=user.reputation_percentage,
        roles=calculate_user_roles(user),
        pending_upgrade=user.pending_role_upgrade,
        is_blacklisted=user.is_blacklisted,
        is_locked=user.is_locked,
    )


@router.get("/users/{user_id}/trust", response_model=TrustResponse)
async def get_user_trust(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_with_access_token),
):
    """
    Get a user's trust score and reputation (own or admin only).
    
    Returns current trust_score, reputation_percentage, roles, and any
    pending role upgrade information.
    
    Regular users can only view their own trust information.
    Admins can view any user's trust information.
    """
    # Check permissions: own trust or admin
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="You can only view your own trust information"
        )
    
    # Load user
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return TrustResponse(
        user_id=user.id,
        trust_score=user.trust_score,
        reputation_percentage=user.reputation_percentage,
        roles=calculate_user_roles(user),
        pending_upgrade=user.pending_role_upgrade,
        is_blacklisted=user.is_blacklisted,
        is_locked=user.is_locked,
    )


@router.get("/users/{user_id}/trust/history", response_model=TrustHistoryResponse)
async def get_user_trust_history(
    user_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=100, description="Number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_with_access_token),
):
    """
    Get paginated trust history for a user (admin only).
    
    Returns all trust score adjustments with source, reason, and timestamp.
    Useful for auditing and understanding how a user's trust evolved.
    
    Requires: Admin authentication
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Only administrators can view trust history"
        )
    
    # Verify user exists
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get history
    history, total = await get_trust_history(db, user_id, limit, offset)
    
    return TrustHistoryResponse(
        user_id=user_id,
        items=[
            TrustHistoryItem(
                id=h.id,
                delta=h.delta,
                reason=h.reason,
                source=h.source,
                old_score=h.old_score,
                new_score=h.new_score,
                created_at=h.created_at,
            )
            for h in history
        ],
        total=total,
        limit=limit,
        offset=offset,
    )