"""
Pydantic schemas for all event types emitted by Auth Service.

Events are published to Redis pub/sub channel 'auth.events' with JSON payloads.
Library Service and other consumers subscribe to this channel.
"""
import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


class BaseEvent(BaseModel):
    """Base event schema with common fields."""
    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat(),
            uuid.UUID: lambda v: str(v),
        }
    )
    
    event: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now())


class UserCreatedEvent(BaseEvent):
    """Emitted when a new user registers."""
    event: Literal["user.created"] = "user.created"
    user_id: uuid.UUID
    email: str
    name: str
    roles: list[str]
    trust_score: int


class UserVerifiedEvent(BaseEvent):
    """Emitted when user completes email verification."""
    event: Literal["user.verified"] = "user.verified"
    user_id: uuid.UUID
    email: str
    verified_at: datetime


class UserTrustUpdatedEvent(BaseEvent):
    """Emitted when user's trust score changes."""
    event: Literal["user.trust_updated"] = "user.trust_updated"
    user_id: uuid.UUID
    old_score: int
    new_score: int
    delta: int
    reason: str
    source: Literal["manual", "upload", "review", "social", "auto_blacklist"]
    pending_upgrade: Optional[dict] = None  # Contains target_roles and scheduled_at if upgrade pending


class UserRoleUpgradedEvent(BaseEvent):
    """Emitted when role promotion is applied after delay."""
    event: Literal["user.role_upgraded"] = "user.role_upgraded"
    user_id: uuid.UUID
    old_roles: list[str]
    new_roles: list[str]
    trust_score: int
    reputation: float
    reason: str


class UserRoleDowngradedEvent(BaseEvent):
    """Emitted when role demotion occurs immediately."""
    event: Literal["user.role_downgraded"] = "user.role_downgraded"
    user_id: uuid.UUID
    old_roles: list[str]
    new_roles: list[str]
    trust_score: int
    reputation: float
    reason: str


class UserBlacklistedEvent(BaseEvent):
    """Emitted when user is blacklisted (auto or manual)."""
    event: Literal["user.blacklisted"] = "user.blacklisted"
    user_id: uuid.UUID
    trust_score: int
    reason: str
    automatic: bool  # True if auto-blacklisted at trust=0, False if manual


class UserLockedEvent(BaseEvent):
    """Emitted when user is locked due to reports."""
    event: Literal["user.locked"] = "user.locked"
    user_id: uuid.UUID
    report_count: int
    reason: str


# Union type for all events (useful for type checking)
EventType = (
    UserCreatedEvent
    | UserVerifiedEvent
    | UserTrustUpdatedEvent
    | UserRoleUpgradedEvent
    | UserRoleDowngradedEvent
    | UserBlacklistedEvent
    | UserLockedEvent
)
