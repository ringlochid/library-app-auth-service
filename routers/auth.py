from datetime import datetime, timezone
from typing import Annotated
import uuid
from fastapi import APIRouter, Depends, HTTPException, Response, Request, Cookie
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import User, RefreshToken
from app.security import (
    _now_utc,
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    get_current_user_with_access_token,
    get_current_user_with_refresh_token,
    decode_refresh_token,
)
from app.schemas.user import UserCreate, UserRead, UserLogIn
from app.schemas.token import AccessTokenResponse
from app.settings import settings
from app.services.auth_tokens import reuse_detection
from redis.asyncio import Redis
from app.redis_client import get_redis
from app.cache import (
    make_access_blacklist_key,
    make_access_key,
    cache_access,
    get_access,
    cache_access_to_bl,
    token_bucket_allow,
    make_rate_limit_key,
)


def get_request_meta(request: Request) -> dict:
    meta = getattr(request.state, "meta", None)
    if meta is None:
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        meta = {"ip": ip, "user_agent": user_agent}
    return meta


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where((User.email == user.email) | (User.name == user.name))
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User name or email already exist")

    hashed_pwd = hash_password(user.password)
    new_user = User(name=user.name, email=user.email, hashed_password=hashed_pwd)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/login", response_model=AccessTokenResponse)
async def user_login(
    user: UserLogIn,
    response: Response,
    db: AsyncSession = Depends(get_db),
    meta: dict = Depends(get_request_meta),
    r: Redis = Depends(get_redis),
):
    ip = meta.get("ip") if meta else None
    allowed, remaining = await token_bucket_allow(
        make_rate_limit_key("login", ip or "unknown"),
        capacity=5,
        refill_tokens=5,
        refill_period_seconds=60,
        r=r,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many login attempts")
    if not user.email and not user.name:
        raise HTTPException(
            status_code=400, detail="Please use the user name or email to log in"
        )
    if user.email and user.name:
        raise HTTPException(
            status_code=400, detail="Provide only one of username or email"
        )

    if user.email:
        stmt = select(User).where(User.email == user.email)
    else:
        stmt = select(User).where(User.name == user.name)

    curr_user = (await db.execute(stmt)).scalar_one_or_none()

    if not curr_user:
        raise HTTPException(status_code=401, detail="User not found")

    ok, new_hash = verify_password(user.password, curr_user.hashed_password)
    if not ok:
        raise HTTPException(status_code=401, detail="Password incorrect")

    if new_hash is not None:
        curr_user.hashed_password = new_hash

    if not curr_user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive")

    key = make_access_key(curr_user.id)
    cached = await get_access(key, r)
    if cached:
        bl_key = make_access_blacklist_key(cached)
        await cache_access_to_bl(bl_key, r)

    access_token, ac_jti = create_access_token(curr_user.id, curr_user.is_admin)

    await cache_access(key, ac_jti, r)

    family_id = uuid.uuid4()
    refresh_token_details = create_refresh_token(curr_user.id, family_id)
    refresh_token = refresh_token_details["token"]
    jti = refresh_token_details["payload"]["jti"]
    issued_at = datetime.fromtimestamp(
        refresh_token_details["payload"]["iat"], tz=timezone.utc
    )
    expires_at = datetime.fromtimestamp(
        refresh_token_details["payload"]["exp"], tz=timezone.utc
    )

    user_agent = meta["user_agent"]
    ip_address = meta["ip"]
    new_refresh_token = RefreshToken(
        jti=jti,
        family_id=family_id,
        user_id=curr_user.id,
        issued_at=issued_at,
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )

    db.add(new_refresh_token)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/auth",
    )

    await db.commit()
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/refresh", response_model=AccessTokenResponse)
async def reissue_access_token(
    response: Response,
    refresh_token: str | None = Cookie(None),
    user: User = Depends(get_current_user_with_refresh_token),
    db: AsyncSession = Depends(get_db),
    meta: dict = Depends(get_request_meta),
    r: Redis = Depends(get_redis),
):
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Token not found")

    payload = decode_refresh_token(refresh_token)
    ip = meta.get("ip") if meta else None
    allowed, remaining = await token_bucket_allow(
        make_rate_limit_key("refresh", ip or "unknown"),
        capacity=30,
        refill_tokens=30,
        refill_period_seconds=60,
        r=r,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many refresh attempts")
    family_id = uuid.UUID(payload["family_id"])
    old_refresh_token = await reuse_detection(
        user_id=user.id,
        jti=payload["jti"],
        family_id=family_id,
        db=db,
    )
    old_refresh_token.is_current = False

    refresh_token_details = create_refresh_token(user.id, family_id)
    new_refresh_token_str = refresh_token_details["token"]
    rt_payload = refresh_token_details["payload"]
    issued_at = datetime.fromtimestamp(rt_payload["iat"], tz=timezone.utc)
    expires_at = datetime.fromtimestamp(rt_payload["exp"], tz=timezone.utc)

    new_refresh_token = RefreshToken(
        jti=rt_payload["jti"],
        family_id=family_id,
        user_id=user.id,
        issued_at=issued_at,
        expires_at=expires_at,
        user_agent=meta.get("user_agent") if meta else None,
        ip_address=meta.get("ip") if meta else None,
    )
    db.add(new_refresh_token)

    await db.commit()
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token_str,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/auth",
    )
    key = make_access_key(user.id)
    cached = await get_access(key, r)
    if cached:
        bl_key = make_access_blacklist_key(cached)
        await cache_access_to_bl(bl_key, r)
    new_access_token, ac_jti = create_access_token(user.id, user.is_admin)
    await cache_access(key, ac_jti, r)
    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout", status_code=204)
async def revoke_refresh_token(
    response: Response,
    all: bool = False,
    meta: dict = Depends(get_request_meta),
    user: User = Depends(get_current_user_with_refresh_token),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
):
    user_agent = meta["user_agent"]

    for rt in user.refresh_tokens:
        if rt.revoked or rt.expires_at < _now_utc():
            continue
        if not all and rt.user_agent and rt.user_agent != user_agent:
            continue
        rt.revoked = True

    response.delete_cookie(key="refresh_token", path="/auth")

    key = make_access_key(user.id)
    cached = await get_access(key, r)
    if cached:
        bl_key = make_access_blacklist_key(cached)
        await cache_access_to_bl(bl_key, r)

    await db.commit()


@router.get("/me", response_model=UserRead)
async def who_am_i(user: User = Depends(get_current_user_with_access_token)):
    return user


@router.get("/admin-only/me", response_model=UserRead)
async def who_am_i_admin(user: User = Depends(get_current_user_with_access_token)):
    if not user.is_admin:
        raise HTTPException(status_code=401, detail="Admins only")
    return user
