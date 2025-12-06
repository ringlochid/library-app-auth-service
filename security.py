from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jwt import ExpiredSignatureError, InvalidTokenError
import uuid
import jwt

from .database import get_db
from .models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def hash_password(pwd : str) -> str:
    return pwd_context.hash(pwd)

def verify_password(pwd: str, hashed_pwd: str) -> tuple[bool, str | None]:
    if not pwd_context.verify(pwd, hashed_pwd):
        return False, None
    if pwd_context.needs_update(hashed_pwd):
        return True, pwd_context.hash(pwd) #upgrade bcrypt to argon2
    return True, None

#config

BASE_DIR = Path(__file__).resolve().parent.parent
PRIVATE_KEY = (BASE_DIR / "keys" / "private_key.pem").read_text()
PUBLIC_KEY = (BASE_DIR / "keys" / "public_key.pem").read_text()
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
ISSUER = "auth-service"
ACCESS_AUDIENCE = "backend-services"

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def create_access_token(
    user_id: int,
    is_admin : bool,
    expires_delta: Optional[timedelta] = None,
) -> str:
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
    return token

def create_refresh_token(
    user_id: int,
    refresh_token_ttl_days: int = 7,
) -> dict:
    now = _now_utc()
    expire = now + timedelta(days=refresh_token_ttl_days)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type": "refresh",
        "iss": ISSUER,
        "aud": ACCESS_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    return {
        "token" : token,
        "payload" : payload
    }


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

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_access_token(token)
    user_id = int(payload["sub"])

    stat = select(User).where(User.id == user_id)
    user = db.execute(stat).scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user