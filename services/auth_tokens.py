import uuid
from fastapi import HTTPException, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.redis_client import get_redis
from app.security import _now_utc
from app.models import RefreshToken
from app.cache import make_access_blacklist_key, cache_access_to_bl


async def reuse_detection(
    user_id: uuid.UUID,
    jti: str,
    family_id: uuid.UUID,
    db: AsyncSession,
    r: Redis = Depends(get_redis),
) -> RefreshToken:
    tokens = (
        (
            await db.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id,
                    RefreshToken.family_id == family_id,
                )
            )
        )
        .scalars()
        .all()
    )

    if not tokens:
        raise HTTPException(401, "Token not found, revoked or expired")

    presented = next((t for t in tokens if t.jti == jti), None)
    if presented is None:
        raise HTTPException(401, "Token not found, revoked or expired")

    now = _now_utc()
    if presented.expires_at <= now or presented.revoked:
        raise HTTPException(401, "Token not found, revoked or expired")

    current = next((t for t in tokens if t.is_current), None)
    if current and current.jti != presented.jti:
        for t in tokens:
            t.revoked = True
            t.is_current = False
        await db.commit()
        raise HTTPException(403, "Token reuse detected, logging out")

    bl_key = make_access_blacklist_key(jti)
    await cache_access_to_bl(bl_key, r)

    return presented
