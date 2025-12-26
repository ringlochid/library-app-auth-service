"""
Pydantic schemas for trust score and reputation management.
"""

import uuid
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class TrustAdjustRequest(BaseModel):
    """Request to adjust a user's trust score."""

    delta: int = Field(..., description="Change in trust score (can be negative)")
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable reason for adjustment",
    )
    source: Literal["manual", "upload", "review", "social", "auto_blacklist"] = Field(
        default="manual", description="Source of the trust adjustment"
    )


class SubmissionAdjustRequest(BaseModel):
    """Request to adjust a submission's trust score."""

    total_delta: int = Field(
        ..., description="Change in total submission count (can be negative)"
    )
    successful_delta: int = Field(
        ..., description="Change in successful submission count (can be negative)"
    )

    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable reason for adjustment",
    )
    source: Literal["manual", "upload", "review", "social", "auto_blacklist"] = Field(
        default="manual", description="Source of the trust adjustment"
    )


class BaseTrustInfo(BaseModel):
    user_id: uuid.UUID
    trust_score: int
    reputation_percentage: float
    roles: list[str]
    pending_upgrade: dict | None = Field(None)
    is_blacklisted: bool
    is_locked: bool


class TrustResponse(BaseTrustInfo):
    pass


class SubmissionResponse(BaseTrustInfo):
    pass


class TrustHistoryItem(BaseModel):
    """Single trust history record."""

    id: uuid.UUID
    delta: int
    reason: str | None
    source: str
    old_score: int
    new_score: int
    created_at: datetime


class TrustHistoryResponse(BaseModel):
    """Paginated trust history response."""

    user_id: uuid.UUID
    items: list[TrustHistoryItem]
    total: int
    limit: int
    offset: int
