from datetime import timedelta
from app.schemas.trust import SubmissionResponse
from app.schemas.trust import SubmissionAdjustRequest
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from redis.asyncio import Redis

from app.database import get_db
from app.redis_client import get_redis
from app.cache import (
    cache_user_profile,
    get_cached_user_existence,
    cache_user_existence,
    get_cached_user_profile,
    token_bucket_allow,
    make_rate_limit_key,
    make_user_info_key,
    make_user_profile_key,
)
from app.settings import settings
from app.models import User
from app.security import get_current_user_with_access_token, verify_password, _now_utc
from app.dependencies.service_auth import verify_service_token
from app.schemas.user import UserExistsResponse, UserProfile, UserRead, UserUpdate
from app.schemas.trust import (
    TrustAdjustRequest,
    TrustResponse,
    TrustHistoryResponse,
    TrustHistoryItem,
)
from app.services.trust import (
    adjust_trust_score,
    get_trust_history,
    recalculate_reputation,
)
from app.rbac import calculate_user_roles

router = APIRouter(prefix="/user", tags=["user services"])


@router.get("/me", response_model=UserRead)
async def who_am_i(user: User = Depends(get_current_user_with_access_token)):
    return user


@router.get("/admin/me", response_model=UserRead)
async def who_am_i_admin(user: User = Depends(get_current_user_with_access_token)):
    if not user.is_admin:
        raise HTTPException(status_code=401, detail="Admins only")
    return user


@router.patch("/me/update", response_model=UserRead)
async def update_user(
    data: UserUpdate,
    user: User = Depends(get_current_user_with_access_token),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
):
    allowed, remaining = await token_bucket_allow(
        make_rate_limit_key("user_update", str(user.id)),
        capacity=settings.RATE_LIMIT_USER_UPDATE_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_USER_UPDATE_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_USER_UPDATE_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for user {user.id}. Try again later.",
        )
    is_name_changed = False
    if data.name:
        query = select(User).where(User.name == data.name)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Name already exists")
        old_name = user.name
        user.name = data.name
        is_name_changed = True
    if data.bio is not None:
        user.bio = data.bio
    if data.preferences is not None:
        user.preferences = data.preferences.model_dump() if data.preferences else None
    await db.commit()
    await db.refresh(user)
    await r.delete(make_user_info_key(user.id))
    await r.delete(make_user_profile_key(user.id, None))
    if is_name_changed:
        await r.delete(make_user_profile_key(None, old_name))
        await r.delete(make_user_profile_key(None, user.name))
    return user


@router.patch("/me/email")
async def update_email(
    data: "UserEmailUpdate",
    user: User = Depends(get_current_user_with_access_token),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
):
    """
    Change user's email address.

    Flow:
    1. Verify current password
    2. Check new email is not taken
    3. Update email, clear email_verified_at, set expires_at to 24h
    4. User must verify new email within 24 hours or account expires

    After this, user will have 'unverified' role until they verify.
    """
    # Rate limit
    allowed, _ = await token_bucket_allow(
        make_rate_limit_key("email_change", str(user.id)),
        capacity=settings.RATE_LIMIT_USER_UPDATE_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_USER_UPDATE_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_USER_UPDATE_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many email change attempts. Try again later.",
        )

    # Verify password
    ok, _ = verify_password(data.password, user.hashed_password)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid password")

    new_email = data.email.lower()
    if new_email == user.email:
        raise HTTPException(status_code=400, detail="New email is the same as current")

    existing = await db.execute(select(User).where(User.email == new_email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already in use")

    # Update email, clear verification, set expiry
    user.email = new_email
    user.email_verified_at = None
    user.expires_at = _now_utc() + timedelta(days=settings.UNVERIFIED_USER_EXPIRE_DAYS)

    await db.commit()
    await db.refresh(user)

    # Clear all caches for this user
    await r.delete(make_user_info_key(user.id))
    await r.delete(make_user_profile_key(user.id, None))
    await r.delete(make_user_profile_key(None, user.name))

    return {
        "message": f"Email changed to {new_email}. Please verify within {settings.UNVERIFIED_USER_EXPIRE_DAYS} days.",
        "email": new_email,
        "expires_at": user.expires_at.isoformat() if user.expires_at else None,
    }


# Forward reference for UserEmailUpdate
from app.schemas.user import UserEmailUpdate


@router.post(
    "/admin/users/{user_id}/submissions/adjust", response_model=SubmissionResponse
)
async def adjust_user_submissions(
    user_id: uuid.UUID,
    payload: SubmissionAdjustRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
    _service_auth: None = Depends(verify_service_token),
):
    """
    Adjust a user's total_submissions and successful_submissions (admin/service only).
    """
    allowed, remaining = await token_bucket_allow(
        make_rate_limit_key("submission_adjust", str(user_id)),
        capacity=settings.RATE_LIMIT_SUBMISSION_ADJUST_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_SUBMISSION_ADJUST_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_SUBMISSION_ADJUST_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for user {user_id}. Try again later.",
        )
    query = select(User).where(User.id == user_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.total_submissions = max(0, user.total_submissions + payload.total_delta)
    user.successful_submissions = max(
        0, user.successful_submissions + payload.successful_delta
    )

    try:
        # Pass user object to avoid redundant DB query
        updated_user = await recalculate_reputation(db=db, user=user)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return SubmissionResponse(
        user_id=updated_user.id,
        trust_score=updated_user.trust_score,
        reputation_percentage=updated_user.reputation_percentage,
        roles=calculate_user_roles(updated_user),
        pending_upgrade=updated_user.pending_role_upgrade,
        is_blacklisted=updated_user.is_blacklisted,
        is_locked=updated_user.is_locked,
    )


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
            detail=f"Rate limit exceeded for user {user_id}. Try again later.",
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
            status_code=403, detail="You can only view your own trust information"
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
            status_code=403, detail="Only administrators can view trust history"
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


@router.get("/check/{user_id}", response_model=UserExistsResponse)
@router.get("/check", response_model=UserExistsResponse)
async def check_user_existence(
    user_id: uuid.UUID | None = None,
    name: str | None = Query(
        None, description="Optional name parameter for future use"
    ),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
    _x_service_auth: None = Depends(verify_service_token),
):
    if not user_id and not name:
        raise HTTPException(
            status_code=400, detail="Either user_id or name must be provided"
        )
    rl_key = make_rate_limit_key("user_check", str(user_id) if user_id else name)
    allowed, _ = await token_bucket_allow(
        rl_key,
        capacity=settings.RATE_LIMIT_USER_CHECK_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_USER_CHECK_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_USER_CHECK_REFILL_PERIOD_SECONDS,
        r=r,
    )
    cached = await get_cached_user_existence(user_id, name, r)
    if cached is not None:
        return cached
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later.",
        )
    stmt = select(User)
    if user_id:
        stmt = stmt.where(User.id == user_id)
    elif name:
        stmt = stmt.where(User.name == name)
    raw = await db.execute(stmt)
    user = raw.scalar_one_or_none()
    if not user:
        return UserExistsResponse(exists=False)

    data = {
        "exists": True,
        "user_id": user.id,
        "is_verified": user.email_verified_at is not None,
        "is_active": user.is_active,
        "is_locked": user.is_locked,
        "is_blacklisted": user.is_blacklisted,
    }

    await cache_user_existence(user_id, name, data, r)
    return data


# public endpoint to show user profile
@router.get("/profile/{user_id}", response_model=UserProfile)
@router.get("/profile", response_model=UserProfile)
async def get_user_profile(
    user_id: uuid.UUID | None = None,
    name: str | None = Query(
        None, description="Optional name parameter for future use"
    ),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
):
    if not user_id and not name:
        raise HTTPException(
            status_code=400, detail="Either user_id or name must be provided"
        )
    cached = await get_cached_user_profile(user_id, name, r)
    if cached is not None:
        return cached
    stmt = select(User)
    if user_id:
        stmt = stmt.where(User.id == user_id)
    elif name:
        stmt = stmt.where(User.name == name)
    raw = await db.execute(stmt)
    user = raw.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    data = UserProfile.model_validate(user).model_dump()
    await cache_user_profile(user_id, name, data, r)
    return data
