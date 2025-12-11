from datetime import datetime
from pydantic import BaseModel

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
    id: int
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True