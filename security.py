from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import HTTPException, status
from passlib.context import CryptContext
import jwt
import uuid

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
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    now = _now_utc()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": "access",
        "iss": ISSUER,
        "aud": ACCESS_AUDIENCE,
        "iat": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "nbf": now,
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
    return token