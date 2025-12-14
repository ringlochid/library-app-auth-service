"""
Pydantic schemas for content reporting system (Phase 4).
"""
from datetime import datetime
from typing import Literal
import uuid
from pydantic import BaseModel, Field, field_validator


class ReportTarget(BaseModel):
    """Target of report: specific edit action from Library Service edit_history."""
    
    content_type: Literal["book", "author", "collection"] = Field(
        ..., description="Type of content"
    )
    content_id: int = Field(..., description="ID of content in Library Service", gt=0)
    edit_id: int = Field(..., description="ID of specific edit in edit_history", gt=0)
    action: Literal["create", "update", "delete", "publish"] = Field(
        ..., description="Type of action being reported"
    )
    actor_id: uuid.UUID = Field(..., description="UUID of user who performed the action")


class ReportSubmitRequest(BaseModel):
    """Request to submit a content report."""
    
    target: ReportTarget
    reason: str = Field(
        ..., 
        min_length=10, 
        max_length=500,
        description="Explanation of why this edit should be reviewed"
    )
    category: Literal["spam", "inappropriate", "vandalism", "copyright", "other"] = Field(
        ..., description="Category of abuse"
    )


class ReportResponse(BaseModel):
    """Response after submitting or reviewing a report."""
    
    id: uuid.UUID
    reporter_id: uuid.UUID
    target: dict  # JSONB as dict
    reason: str
    category: str
    status: Literal["pending", "approved", "rejected"]
    reviewed_by: uuid.UUID | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class ReportReviewRequest(BaseModel):
    """Request to review a report (admin only)."""
    
    action: Literal["approve", "reject"] = Field(
        ..., description="Approve or reject this report"
    )
    notes: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Admin notes explaining the decision"
    )


class ReportListItem(BaseModel):
    """Simplified report info for list view."""
    
    id: uuid.UUID
    reporter_id: uuid.UUID
    target: dict
    reason: str
    category: str
    status: str
    created_at: datetime
    reviewed_at: datetime | None = None
    
    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Paginated list of reports."""
    
    items: list[ReportListItem]
    total: int
    limit: int
    offset: int


class UnlockUserResponse(BaseModel):
    """Response after unlocking a user."""
    
    user_id: uuid.UUID
    is_locked: bool
    message: str
