import hashlib
from datetime import datetime, timezone, timedelta
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request, Cookie
from sqlalchemy import select, func, text
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import User, RefreshToken, VerificationToken
from app.schemas.shared import EmailBase
from app.security import (
    _now_utc,
    create_verify_email_token,
    decode_email_verification_token,
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    get_current_user_with_access_token,
    get_current_user_with_refresh_token,
    decode_refresh_token,
)
from app.schemas.user import (
    UserCreate,
    UserRead,
    UserLogIn,
    AvatarUploadRequest,
    AvatarUploadResponse,
    AvatarCommitRequest,
)
from app.schemas.token import AccessTokenResponse
from app.services.email import send_email
from app.tasks.email import send_verify_email
from app.settings import settings
from app.services.auth_tokens import reuse_detection
from app.services.storage import get_s3_client
from redis.asyncio import Redis
from app.redis_client import get_redis
from app.cache import (
    make_access_blacklist_key,
    make_access_key,
    cache_access,
    get_access,
    cache_access_to_bl,
    delete_cached_user,
    token_bucket_allow,
    make_rate_limit_key,
)
import uuid as uuid_pkg


def get_request_meta(request: Request) -> dict:
    meta = getattr(request.state, "meta", None)
    if meta is None:
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        meta = {"ip": ip, "user_agent": user_agent}
    return meta


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead)
async def create_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_db),
    meta: dict = Depends(get_request_meta),
    r: Redis = Depends(get_redis),
):
    ip = meta.get("ip") if meta else None
    allowed, _ = await token_bucket_allow(
        make_rate_limit_key("register", ip or "unknown"),
        capacity=settings.RATE_LIMIT_REGISTER_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_REGISTER_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_REGISTER_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many registration attempts")
    stmt = select(User).where((User.email == user.email) | (User.name == user.name))
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User name or email already exist")

    hashed_pwd = hash_password(user.password)
    new_user = User(name=user.name, email=user.email, hashed_password=hashed_pwd)
    db.add(new_user)
    # set expiry for unverified accounts
    new_user.expires_at = _now_utc() + timedelta(
        days=settings.UNVERIFIED_USER_EXPIRE_DAYS
    )
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
        capacity=settings.RATE_LIMIT_LOGIN_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_LOGIN_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_LOGIN_REFILL_PERIOD_SECONDS,
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

    if curr_user.expires_at and curr_user.expires_at <= _now_utc():
        raise HTTPException(status_code=403, detail="Account expired")

    ok, new_hash = verify_password(user.password, curr_user.hashed_password)
    if not ok:
        raise HTTPException(status_code=401, detail="Password incorrect")

    if not curr_user.email_verified_at:
        raise HTTPException(status_code=403, detail="Email not verified")

    user_mutated = False
    if new_hash is not None:
        curr_user.hashed_password = new_hash
        user_mutated = True

    if not curr_user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive")

    key = make_access_key(curr_user.id)
    cached = await get_access(key, r)
    if cached:
        cached_jti = cached.get("jti")
        cached_exp = cached.get("exp")
        bl_ttl = (
            max(int(cached_exp - _now_utc().timestamp()), 1)
            if cached_exp
            else settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        bl_key = make_access_blacklist_key(cached_jti)
        await cache_access_to_bl(bl_key, r, ttl=bl_ttl)

    access_token, ac_jti, ac_exp = create_access_token(curr_user.id, curr_user.is_admin)

    await cache_access(key, ac_jti, ac_exp, r)

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
    if user_mutated:
        await delete_cached_user(curr_user.id, r)
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
    now_ts = _now_utc().timestamp()
    ip = meta.get("ip") if meta else None
    allowed, remaining = await token_bucket_allow(
        make_rate_limit_key("refresh", ip or "unknown"),
        capacity=settings.RATE_LIMIT_REFRESH_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_REFRESH_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_REFRESH_REFILL_PERIOD_SECONDS,
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
        cached_jti = cached.get("jti")
        cached_exp = cached.get("exp")
        bl_ttl = (
            max(int(cached_exp - now_ts), 1)
            if cached_exp
            else settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        bl_key = make_access_blacklist_key(cached_jti)
        await cache_access_to_bl(bl_key, r, ttl=bl_ttl)
    new_access_token, ac_jti, ac_exp = create_access_token(user.id, user.is_admin)
    await cache_access(key, ac_jti, ac_exp, r)
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
        cached_jti = cached.get("jti")
        cached_exp = cached.get("exp")
        bl_ttl = (
            max(int(cached_exp - _now_utc().timestamp()), 1)
            if cached_exp
            else settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        bl_key = make_access_blacklist_key(cached_jti)
        await cache_access_to_bl(bl_key, r, ttl=bl_ttl)

    await db.commit()


@router.post("/verify-email/send", status_code=202)
async def send_email_verification(
    payload: EmailBase,
    db: AsyncSession = Depends(get_db),
    meta: dict = Depends(get_request_meta),
    r: Redis = Depends(get_redis),
):
    ip = meta.get("ip") if meta else None
    email = payload.email
    if not email:
        raise HTTPException(status_code=400, detail="email not valid")
    # IP rate limit
    allowed_ip, _ = await token_bucket_allow(
        make_rate_limit_key("verify_send", ip or "unknown"),
        capacity=settings.RATE_LIMIT_VERIFY_SEND_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_VERIFY_SEND_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_VERIFY_SEND_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed_ip:
        raise HTTPException(
            status_code=429, detail="Too many verification requests from this IP"
        )
    # domain rate limit
    domain = email.split("@")[-1].lower()
    allowed_domain, _ = await token_bucket_allow(
        make_rate_limit_key("verify_domain", domain),
        capacity=settings.RATE_LIMIT_VERIFY_DOMAIN_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_VERIFY_DOMAIN_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_VERIFY_DOMAIN_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed_domain:
        raise HTTPException(
            status_code=429, detail="Too many verification requests for this domain"
        )
    # email rate limit
    allowed_email, _ = await token_bucket_allow(
        make_rate_limit_key("verify_email", email.lower()),
        capacity=settings.RATE_LIMIT_VERIFY_EMAIL_CAPACITY,
        refill_tokens=settings.RATE_LIMIT_VERIFY_EMAIL_REFILL_TOKENS,
        refill_period_seconds=settings.RATE_LIMIT_VERIFY_EMAIL_REFILL_PERIOD_SECONDS,
        r=r,
    )
    if not allowed_email:
        raise HTTPException(
            status_code=429, detail="Too many verification requests for this email"
        )
    stmt = (
        select(User)
        .options(selectinload(User.verification_tokens))
        .where(User.email == email.lower())
    )
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.email_verified_at is not None:
        raise HTTPException(status_code=400, detail="Email already verified")
    if user.verification_tokens:
        for vt in user.verification_tokens:
            if vt.used_at is None:
                vt.used_at = func.now()
    verification_token_details = create_verify_email_token(user.id, email=email)
    verification_token = verification_token_details["token"]
    digest = hashlib.sha256(verification_token.encode()).hexdigest()
    vt_payload = verification_token_details["payload"]
    new_vt = VerificationToken(
        user_id=user.id,
        token_hash=digest,
        expires_at=datetime.fromtimestamp(vt_payload["exp"], tz=timezone.utc),
        created_at=datetime.fromtimestamp(vt_payload["iat"], tz=timezone.utc),
    )
    db.add(new_vt)
    await db.commit()
    # test
    verify_url = f"{settings.EMAIL_VERIFY_BASE_URL}{verification_token}"
    body = f"your verification link is : {verify_url}"
    send_verify_email(to=email, subject="verification", body=body)


@router.get("/verify-email", status_code=204)
async def commit_email_verification(
    token: str | None = Query(None, description="the email verification token"),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
):
    if token is None:
        raise HTTPException(status_code=400, detail="Token is required")
    payload = decode_email_verification_token(token)
    digest = hashlib.sha256(token.encode()).hexdigest()
    stmt = (
        select(VerificationToken)
        .options(selectinload(VerificationToken.user))
        .where(
            VerificationToken.token_hash == digest,
            VerificationToken.expires_at > func.now(),
            VerificationToken.used_at.is_(None),
            VerificationToken.user_id == uuid.UUID(payload["sub"]),
            VerificationToken.user.has(email=payload["email"].lower()),
        )
    )
    raw_vt = await db.execute(stmt)
    vt = raw_vt.scalar_one_or_none()
    if not vt:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    vt.used_at = func.now()
    # mark user as verified
    user = vt.user
    if user:
        if user.email_verified_at is None:
            user.email_verified_at = func.now()
        user.expires_at = None
    await db.commit()
    if user:
        await delete_cached_user(user.id, r)


@router.get("/me", response_model=UserRead)
async def who_am_i(user: User = Depends(get_current_user_with_access_token)):
    return user


@router.get("/admin-only/me", response_model=UserRead)
async def who_am_i_admin(user: User = Depends(get_current_user_with_access_token)):
    if not user.is_admin:
        raise HTTPException(status_code=401, detail="Admins only")
    return user


# Avatar upload flow
@router.post("/avatar/upload", response_model=AvatarUploadResponse)
async def create_avatar_upload(
    payload: AvatarUploadRequest,
    user: User = Depends(get_current_user_with_access_token),
    s3_client = Depends(get_s3_client),
):
    """
    Issue a presigned POST for uploading an avatar to a temporary key.
    """
    key = f"tmp/avatars/{user.id}/{uuid_pkg.uuid4()}"
    try:
        presigned = s3_client.generate_presigned_post(
            Bucket=settings.S3_MEDIA_BUCKET,
            Key=key,
            Fields={"Content-Type": payload.content_type},
            Conditions=[
                ["starts-with", "$Content-Type", "image/"],
                ["content-length-range", 0, settings.AVATAR_MAX_BYTES],
            ],
            ExpiresIn=settings.AVATAR_UPLOAD_EXPIRES_SECONDS,
        )
    except Exception as exc:  # pragma: no cover - passthrough AWS errors
        raise HTTPException(status_code=500, detail="Failed to create upload URL") from exc

    return AvatarUploadResponse(key=key, url=presigned["url"], fields=presigned["fields"])


@router.post("/avatar/commit", status_code=204)
async def commit_avatar(
    payload: AvatarCommitRequest,
    user: User = Depends(get_current_user_with_access_token),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
    s3_client = Depends(get_s3_client),
):
    """
    Finalize an avatar upload: ensure the object exists in tmp/, then move to permanent key.
    """
    tmp_key = payload.key
    expected_prefix = f"tmp/avatars/{user.id}/"
    if not tmp_key.startswith(expected_prefix):
        raise HTTPException(status_code=400, detail="Invalid key")
    bucket = settings.S3_MEDIA_BUCKET
    # ensure object exists in tmp
    try:
        s3_client.head_object(Bucket=bucket, Key=tmp_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Upload not found or expired")

    final_key = f"avatars/{user.id}/{uuid_pkg.uuid4()}"
    try:
        s3_client.copy_object(
            Bucket=bucket,
            CopySource={"Bucket": bucket, "Key": tmp_key},
            Key=final_key,
            MetadataDirective="REPLACE",
        )
        s3_client.delete_object(Bucket=bucket, Key=tmp_key)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to finalize avatar") from exc

    user.avatar_key = final_key
    await db.commit()
    await delete_cached_user(user.id, r)
