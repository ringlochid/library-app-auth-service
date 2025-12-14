from datetime import datetime
import uuid
import re
from pydantic import BaseModel, ConfigDict, field_validator, computed_field
from app.settings import settings


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
    is_blacklisted: bool
    scopes: list[str]
    roles: list[str]  # New RBAC field
    trust_score: int  # New trust/reputation field
    reputation_percentage: float  # New reputation field
    email_verified_at: datetime | None = None
    avatar_key: str | None = None
    bio: str | None = None
    preferences: dict | None = None

    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def avatar_urls(self) -> dict[str, str] | None:
        """Generate public S3 URLs for all avatar size variants."""
        if not self.avatar_key:
            return None
        
        if not settings.S3_MEDIA_BUCKET or not settings.S3_MEDIA_REGION:
            return None
        
        base_url = f"https://{settings.S3_MEDIA_BUCKET}.s3.{settings.S3_MEDIA_REGION}.amazonaws.com"
        
        # Extract the base pattern (assumes key ends with /{size}.{ext})
        # "avatars/user-id/uuid/512.webp" -> "avatars/user-id/uuid"
        parts = self.avatar_key.rsplit("/", 1)
        if len(parts) != 2:
            return None
        
        base_path = parts[0]
        filename = parts[1]
        
        # Extract extension
        if "." not in filename:
            return None
        
        ext = filename.rsplit(".", 1)[1]
        
        # Generate URLs for all target sizes
        return {
            str(size): f"{base_url}/{base_path}/{size}.{ext}"
            for size in settings.AVATAR_TARGET_SIZES
        }


class AvatarUploadRequest(BaseModel):
    content_type: str = "image/jpeg"


class AvatarUploadResponse(BaseModel):
    key: str
    url: str
    fields: dict


class AvatarCommitRequest(BaseModel):
    key: str
