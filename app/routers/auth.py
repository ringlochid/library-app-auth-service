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
    verify_password,
    create_access_token,
    create_refresh_token,
    get_current_user_with_access_token,
    get_current_user_with_refresh_token,
    decode_refresh_token,
)
from app.rbac import calculate_user_roles, get_scopes_for_roles
from app.schemas.user import (
    UserCreate,
    UserRead,
    UserLogIn,
    AvatarUploadRequest,
    AvatarUploadResponse,
    AvatarCommitRequest,
)
from app.schemas.token import AccessTokenResponse
from app.schemas.session import SessionItem, SessionListResponse
from app.tasks.email import send_verify_email
from app.tasks.media import process_upload
from app.settings import settings
from app.services.auth_tokens import reuse_detection
from app.services.storage import get_s3_client
from redis.asyncio import Redis
from app.redis_client import get_redis
from app.cache import (
    create_avatar_claim,
    delete_cached_user_existence,
    delete_cached_user_profile,
    make_access_blacklist_key,
    make_access_key,
    cache_access,
    get_access,
    cache_access_to_bl,
    delete_cached_user_info,
    token_bucket_allow,
    make_rate_limit_key,
    consume_avatar_claim,
)
import uuid as uuid_pkg
import time
from typing import Set


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

    # Calculate roles and scopes for RBAC
    roles = calculate_user_roles(curr_user)
    scopes = get_scopes_for_roles(roles)
    
    access_token, ac_jti, ac_exp = create_access_token(
        curr_user.id, 
        curr_user.is_admin,
        roles=roles,
        scopes=scopes,
        trust_score=curr_user.trust_score,
        reputation_percentage=curr_user.reputation_percentage
    )

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
        last_used_at=issued_at,  # Phase 5: Track initial usage
        last_used_ip=ip_address,
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
        await delete_cached_user_info(curr_user.id, r)
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
    # Phase 5: Track last usage before rotating
    old_refresh_token.last_used_at = _now_utc()
    old_refresh_token.last_used_ip = meta.get("ip") if meta else None

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
        last_used_at=issued_at,  # Phase 5: Track initial usage
        last_used_ip=meta.get("ip") if meta else None,
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
    
    # Calculate roles and scopes for RBAC
    roles = calculate_user_roles(user)
    scopes = get_scopes_for_roles(roles)
    
    new_access_token, ac_jti, ac_exp = create_access_token(
        user.id, 
        user.is_admin,
        roles=roles,
        scopes=scopes,
        trust_score=user.trust_score,
        reputation_percentage=user.reputation_percentage
    )
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
    verify_url = f"{settings.EMAIL_VERIFY_BASE_URL}{verification_token}"
    
    # Create a formatted HTML body for the verification email
    body = f"""
    <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .container {{ max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }}
                .header {{ font-size: 24px; font-weight: bold; margin-bottom: 20px; text-align: center; }}
                .content {{ font-size: 16px; line-height: 1.5; }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    margin: 20px 0;
                    background-color: #007bff;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .footer {{ font-size: 12px; color: #888; margin-top: 20px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">Verify Your Email Address</div>
                <div class="content">
                    <p>Thanks for registering! Please click the button below to verify your email address.</p>
                    <a href="{verify_url}" class="button">Verify Email</a>
                    <p>If you cannot click the button, please copy and paste this link into your browser:</p>
                    <p><a href="{verify_url}">{verify_url}</a></p>
                    <p>This link will expire in {settings.EMAIL_VERIFY_EXPIRE_MINUTES} minutes.</p>
                </div>
                <div class="footer">
                    If you did not request this email, please ignore it.
                </div>
            </div>
        </body>
    </html>
    """
    send_verify_email.delay(to=email, subject="Verify Your Email", body=body)


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
        await db.refresh(user)
        await delete_cached_user_info(user.id, r)
        await delete_cached_user_existence(user.id, None, r)
        await delete_cached_user_existence(None, user.name, r)
        await delete_cached_user_profile(user.id, None, r)
        await delete_cached_user_profile(None, user.name, r)


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    user: User = Depends(get_current_user_with_access_token),
    db: AsyncSession = Depends(get_db),
):
    """
    List all active refresh tokens (sessions) for the current user.
    
    Returns session details including:
    - Device info (user_agent, parsed on client)
    - Location (IP addresses)
    - Timestamps (issued_at, last_used_at, expires_at)
    - Current session flag (is_current)
    
    Use this to show users where they're logged in.
    """
    # Load user's refresh tokens
    stmt = (
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > _now_utc()
        )
        .order_by(RefreshToken.last_used_at.desc().nulls_last())
    )
    result = await db.execute(stmt)
    tokens = result.scalars().all()
    
    sessions = [
        SessionItem(
            id=token.id,
            family_id=str(token.family_id),
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            last_used_at=token.last_used_at,
            user_agent=token.user_agent,
            ip_address=token.ip_address,
            last_used_ip=token.last_used_ip,
            is_current=token.is_current,
        )
        for token in tokens
    ]
    
    return SessionListResponse(
        sessions=sessions,
        total=len(sessions)
    )

@router.post("/avatar/upload", response_model=AvatarUploadResponse)
async def create_avatar_upload(
    payload: AvatarUploadRequest,
    user: User = Depends(get_current_user_with_access_token),
    s3_client = Depends(get_s3_client),
    meta: dict = Depends(get_request_meta),
    r : Redis = Depends(get_redis),
):
    """
    Issue a presigned POST for uploading an avatar to a temporary key.
    """
    allowed_mimes = set(settings.AVATAR_ALLOWED_MIME_TYPES)
    if payload.content_type not in allowed_mimes:
        raise HTTPException(status_code=400, detail="Unsupported avatar content type")

    ip = meta["ip"]
    rl_key = make_rate_limit_key("avatar_upload", str(ip))
    allowed, _ = await token_bucket_allow(
            key=rl_key,
            capacity=settings.RATE_LIMIT_AVATAR_UPLOAD_CAPACITY,
            refill_tokens=settings.RATE_LIMIT_AVATAR_UPLOAD_REFILL_TOKENS,
            refill_period_seconds=settings.RATE_LIMIT_AVATAR_UPLOAD_REFILL_PERIOD_SECONDS,
            r = r,
        )
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many upload requests for this ip")

    path_id = uuid.uuid4()
    expires_ts = int(_now_utc().timestamp()) + settings.AVATAR_UPLOAD_EXPIRES_SECONDS
    ttl = settings.AVATAR_UPLOAD_EXPIRES_SECONDS + 300
    key = f"tmp/avatars/{user.id}/{path_id}"
    try:
        presigned = s3_client.generate_presigned_post(
            Bucket=settings.S3_MEDIA_BUCKET,
            Key=key,
            Fields={"Content-Type": payload.content_type},
            Conditions=[
                ["starts-with", "$Content-Type", "image/"],
                ["content-length-range", 1, settings.AVATAR_MAX_BYTES],
            ],
            ExpiresIn=settings.AVATAR_UPLOAD_EXPIRES_SECONDS,
        )
    except Exception as exc:  # passthrough AWS errors
        raise HTTPException(status_code=500, detail="Failed to create upload URL") from exc

    await create_avatar_claim(
        user_id=user.id,
        upload_id=path_id,
        s3_key=key,
        expected_mime=payload.content_type,
        max_bytes=settings.AVATAR_MAX_BYTES,
        expires_at_ts=expires_ts,
        ttl_seconds=ttl,
        r=r,
    )
    return AvatarUploadResponse(key=key, url=presigned["url"], fields=presigned["fields"])


@router.post("/avatar/commit", status_code=204)
async def commit_avatar(
    payload: AvatarCommitRequest,
    user: User = Depends(get_current_user_with_access_token),
    meta: dict = Depends(get_request_meta),
    r: Redis = Depends(get_redis),
    s3_client = Depends(get_s3_client),
):
    ip = meta["ip"]
    rl_key = make_rate_limit_key("avatar_commit", str(ip))
    allowed, _ = await token_bucket_allow(
            key=rl_key,
            capacity=settings.RATE_LIMIT_AVATAR_COMMIT_CAPACITY,
            refill_tokens=settings.RATE_LIMIT_AVATAR_COMMIT_REFILL_TOKENS,
            refill_period_seconds=settings.RATE_LIMIT_AVATAR_COMMIT_REFILL_PERIOD_SECONDS,
            r = r,
        )
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many commit requests for this ip")
    
    tmp_key = payload.key
    expected_prefix = f"tmp/avatars/{user.id}/"
    if not tmp_key.startswith(expected_prefix):
        raise HTTPException(status_code=400, detail="Invalid key")

    parts = tmp_key.split("/")
    if len(parts) != 4:
        raise HTTPException(status_code=400, detail="Invalid key format")

    leaf = parts[3]
    leaf_uuid = leaf
    if "." in leaf:
        leaf_uuid, ext = leaf.rsplit(".", 1)
        if "." in leaf_uuid:
            raise HTTPException(status_code=400, detail="Invalid filename")
        # derive allowed extensions from allowed MIME types
        mime_to_ext = {
            "image/jpeg": {"jpg", "jpeg"},
            "image/png": {"png"},
            "image/webp": {"webp"},
            "image/avif": {"avif"},
        }
        allowed_exts: Set[str] = set()
        for mime in settings.AVATAR_ALLOWED_MIME_TYPES:
            allowed_exts.update(mime_to_ext.get(mime, set()))
        if ext.lower() not in allowed_exts:
            raise HTTPException(status_code=400, detail="Disallowed file extension")

    try:
        upload_id = uuid_pkg.UUID(leaf_uuid)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid upload id")

    claim = await consume_avatar_claim(user.id, upload_id, r)
    if not claim:
        raise HTTPException(status_code=400, detail="Upload not found or expired")
    if claim.get("key") != tmp_key:
        raise HTTPException(status_code=400, detail="Claim does not match key")
    exp_ts = claim.get("exp_ts")
    now_ts = int(time.time())
    if exp_ts and now_ts > exp_ts:
        raise HTTPException(status_code=400, detail="Upload claim has expired")

    # fast-fail: ensure object exists and matches claim expectations.
    try:
        head = s3_client.head_object(Bucket=settings.S3_MEDIA_BUCKET, Key=tmp_key)
        size = head.get("ContentLength") or 0
        if size < 1 or size > claim.get("max_bytes", settings.AVATAR_MAX_BYTES):
            raise HTTPException(status_code=400, detail="Upload size invalid")
        content_type = head.get("ContentType")
        expected_mime = claim.get("expected_mime")
        if expected_mime and content_type and content_type != expected_mime:
            raise HTTPException(status_code=400, detail="Upload content type invalid")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Upload not found or expired")

    try:
        process_upload.delay(tmp_key)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to enqueue processing") from exc
