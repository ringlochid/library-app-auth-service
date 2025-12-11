from datetime import datetime
import uuid
from pydantic import BaseModel, ConfigDict

class UserLogIn(BaseModel):
    name : str | None = None
    email : str | None = None
    password: str

class UserBase(BaseModel):
    name: str
    email: str

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_admin: bool
    scopes: list[str]

    model_config = ConfigDict(from_attributes=True)
