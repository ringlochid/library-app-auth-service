from typing import List
from datetime import datetime
from .database import Base
from sqlalchemy import text, DateTime, String, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

class User(Base):
    __tablename__ = 'users'
    id : Mapped[int] = mapped_column(primary_key=True, index= True)
    name : Mapped[str] = mapped_column(String(127), unique=True, index= True)
    email : Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index= True)
    hashed_password : Mapped[str] = mapped_column(String(255), nullable=False)
    is_active : Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("TRUE"))
    is_admin : Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    created_at : Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at : Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"), onupdate=text("CURRENT_TIMESTAMP"))

    refresh_tokens : Mapped[List['RefreshToken']] = relationship(back_populates="user", cascade="all, delete-orphan",)

class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'
    id : Mapped[int] = mapped_column(primary_key=True, index= True)
    jti : Mapped[str] = mapped_column(String(255), unique=True)
    user_id : Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    issued_at : Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at : Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked : Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("FALSE"))
    user_agent : Mapped[str | None] = mapped_column(String(255))
    ip_address : Mapped[str | None] = mapped_column(String(45))

    user : Mapped['User'] = relationship(back_populates="refresh_tokens")
