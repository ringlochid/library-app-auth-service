from datetime import datetime, timezone
from typing import List, Annotated
from fastapi import APIRouter, Depends, HTTPException, Cookie, Header, Response, Request
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select
from ..database import get_db
from ..models import User, RefreshToken
from ..security import hash_password, verify_password, create_access_token, create_refresh_token, get_current_user
from ..schemas.user import UserCreate, UserRead, UserLogIn
from ..schemas.token import LoginResponse

def get_request_meta(
    request: Request,
    user_agent: Annotated[str | None, Header(None, alias="User-Agent")] = None,
):
    ip = request.client.host if request.client else None
    return {"ip": ip, "user_agent": user_agent}

router = APIRouter(prefix='/auth', tags=['auth'])

@router.post('/register', response_model=UserRead)
def create_user(user : UserCreate, db : Session = Depends(get_db)):
    stmt = select(User).where(
        (User.email == user.email) | (User.name == user.name)
    )
    existing = db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail='User name or email already exist')
    hashed_pwd = hash_password(user.password)
    new_user = User(
        name = user.name,
        email = user.email,
        hashed_password = hashed_pwd
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post('/login', response_model=LoginResponse)
def user_login(user : UserLogIn,
               response: Response,
               db : Session = Depends(get_db),
               meta: dict = Depends(get_request_meta),
               ):
    if not user.email and not user.name:
        raise HTTPException(status_code=400, detail='Please use the user name or email to log in')
    if user.email and user.name:
        raise HTTPException(status_code=400, detail="Provide only one of username or email")
    
    if user.email:
        stmt = select(User).where(User.email == user.email)
    else:
        stmt = select(User).where(User.name == user.name)

    curr_user = db.execute(stmt).scalar_one_or_none()

    if not curr_user:
        raise HTTPException(status_code=400, detail='The user information is incorrect')
    
    ok, new_hash = verify_password(user.password, curr_user.hashed_password)
    if not ok:
        raise HTTPException(status_code=400, detail='Password incorrect')

    if new_hash is not None:
        curr_user.hashed_password = new_hash

    if not curr_user.is_active:
        raise HTTPException(status_code=400, detail='User is inactive')
    
    access_token = create_access_token(curr_user.id, curr_user.is_admin)
    refresh_token_details = create_refresh_token(curr_user.id)
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
        jti = jti,
        user_id =  curr_user.id,
        issued_at = issued_at,
        expires_at = expires_at,
        user_agent = user_agent,
        ip_address = ip_address
    )

    db.add(new_refresh_token)

    response.set_cookie(
                        key="refresh_token",
                        value=refresh_token,
                        httponly=True,
                        secure=True,
                        #secure=False #for dev
                        samesite="lax",
                        path="/auth/refresh",
                    )
    
    db.commit()
    return {
        "access_token" : access_token,
        "token_type" : "bearer"
    }
