"""
Session management schemas (Phase 5).
"""
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class SessionItem(BaseModel):
    """Individual session information."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    family_id: str
    issued_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    user_agent: str | None
    ip_address: str | None
    last_used_ip: str | None
    is_current: bool


class SessionListResponse(BaseModel):
    """List of active sessions for a user."""
    sessions: list[SessionItem]
    total: int
