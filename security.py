from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import uuid
import jwt
from fastapi import HTTPException, status, Depends, Cookie
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from passlib.context import CryptContext
from jwt import ExpiredSignatureError, InvalidTokenError
from redis.asyncio import Redis

from app.settings import settings
from app.database import get_db
from app.models import User
from app.redis_client import get_redis
from app.cache import (
    check_access_in_bl,
    make_access_blacklist_key,
    get_cached_user,
    cache_user,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(pwd: str) -> str:
    return pwd_context.hash(pwd)


def verify_password(pwd: str, hashed_pwd: str) -> tuple[bool, str | None]:
    if not pwd_context.verify(pwd, hashed_pwd):
        return False, None
    if pwd_context.needs_update(hashed_pwd):
        return True, pwd_context.hash(pwd)  # upgrade bcrypt to argon2
    return True, None


BASE_DIR = Path(__file__).resolve().parent.parent
PRIVATE_KEY = (BASE_DIR / settings.JWT_PRIVATE_KEY_PATH).read_text()
PUBLIC_KEY = (BASE_DIR / settings.JWT_PUBLIC_KEY_PATH).read_text()
ALGORITHM = settings.JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
EMAIL_VERIFY_EXPIRE_MINUTES = settings.EMAIL_VERIFY_EXPIRE_MINUTES
ISSUER = settings.JWT_ISSUER
ACCESS_AUDIENCE = settings.JWT_AUDIENCE


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    user_id: uuid.UUID,
    is_admin: bool,
    expires_delta: Optional[timedelta] = None,
) -> tuple[str, str, int]:
    now = _now_utc()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type": "access",
        "role": "admin" if is_admin else "user",
        "iss": ISSUER,
        "aud": ACCESS_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    return token, jti, int(expire.timestamp())


def create_refresh_token(
    user_id: uuid.UUID,
    family_id: uuid.UUID,
    refresh_token_ttl_days: int | None = None,
) -> dict:
    now = _now_utc()
    ttl_days = refresh_token_ttl_days or settings.REFRESH_TOKEN_TTL_DAYS
    expire = now + timedelta(days=ttl_days)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "family_id": str(family_id),
        "type": "refresh",
        "iss": ISSUER,
        "aud": ACCESS_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    return {"token": token, "payload": payload}


def create_verify_email_token(
    user_id: uuid.UUID,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> dict:
    now = _now_utc()
    expire = now + (expires_delta or timedelta(minutes=EMAIL_VERIFY_EXPIRE_MINUTES))
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "email": email,
        "type": "email_verification",
        "iss": ISSUER,
        "aud": ACCESS_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    return {"token": token, "payload": payload}


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=ACCESS_AUDIENCE,
            issuer=ISSUER,
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
        )

    return payload


def decode_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=ACCESS_AUDIENCE,
            issuer=ISSUER,
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
        )

    return payload


def decode_email_verification_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=ACCESS_AUDIENCE,
            issuer=ISSUER,
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    if payload.get("type") != "email_verification":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
        )

    return payload


async def get_current_user_with_access_token(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    r: Redis = Depends(get_redis),
) -> User:
    payload = decode_access_token(token)
    bl_key = make_access_blacklist_key(payload["jti"])
    is_bl = await check_access_in_bl(bl_key, r)
    if is_bl:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    user_id = uuid.UUID(payload["sub"])

    cached = await get_cached_user(user_id, r)
    if cached is not None:
        return User(
            id=user_id,
            name=cached["name"],
            email=cached["email"],
            hashed_password="",
            is_active=cached["is_active"],
            is_admin=cached["is_admin"],
            scopes=cached.get("scopes", []),
            created_at=(
                datetime.fromisoformat(cached["created_at"])
                if cached.get("created_at")
                else None
            ),
            updated_at=(
                datetime.fromisoformat(cached["updated_at"])
                if cached.get("updated_at")
                else None
            ),
            email_verified_at=(
                datetime.fromisoformat(cached["email_verified_at"])
                if cached.get("email_verified_at")
                else None
            ),
            expires_at=(
                datetime.fromisoformat(cached["expires_at"])
                if cached.get("expires_at")
                else None
            ),
        )

    stat = select(User).where(User.id == user_id)
    result = await db.execute(stat)
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    if user.expires_at and user.expires_at <= _now_utc():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account expired",
        )
    if user.email_verified_at is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified",
        )

    await cache_user(
        user_id,
        {
            "id": str(user_id),
            "name": user.name,
            "email": user.email,
            "is_active": user.is_active,
            "is_admin": user.is_admin,
            "scopes": user.scopes,
            "created_at": user.created_at.isoformat() if user.created_at else "",
            "updated_at": user.updated_at.isoformat() if user.updated_at else "",
            "email_verified_at": (
                user.email_verified_at.isoformat() if user.email_verified_at else ""
            ),
            "expires_at": user.expires_at.isoformat() if user.expires_at else "",
        },
        r,
    )

    return user


async def get_current_user_with_refresh_token(
    refresh_token: str | None = Cookie(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Token not found")

    payload = decode_refresh_token(refresh_token)
    user_id = uuid.UUID(payload["sub"])

    stmt = (
        select(User)
        .options(selectinload(User.refresh_tokens))
        .where(User.id == user_id)
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    if user.expires_at and user.expires_at <= _now_utc():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account expired",
        )

    return user
