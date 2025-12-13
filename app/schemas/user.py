from datetime import datetime
import uuid
import re
from pydantic import BaseModel, ConfigDict, field_validator


class UserLogIn(BaseModel):
    name: str | None = None
    email: str | None = None
    password: str


class UserBase(BaseModel):
    name: str
    email: str


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        """
        Enforce a basic strong password policy:
        - at least 8 characters
        - at least one lowercase, one uppercase, one digit, and one symbol
        """
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        pattern = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).+$")
        if not pattern.match(v):
            raise ValueError("Password must include upper, lower, digit, and symbol")
        return v.strip()


class UserRead(UserBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_admin: bool
    scopes: list[str]
    email_verified_at: datetime | None = None
    avatar_key: str | None = None
    bio: str | None = None
    preferences: dict | None = None

    model_config = ConfigDict(from_attributes=True)


class AvatarUploadRequest(BaseModel):
    content_type: str = "image/jpeg"


class AvatarUploadResponse(BaseModel):
    key: str
    url: str
    fields: dict


class AvatarCommitRequest(BaseModel):
    key: str
