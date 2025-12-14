from typing import List
from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(127), unique=True, index=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("TRUE")
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    is_blacklisted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    # profile fields
    avatar_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    bio: Mapped[str | None] = mapped_column(String(500), nullable=True)
    preferences: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    
    # roles and permissions
    roles: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[\"user\"]'::jsonb")
    )
    trust_score: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    reputation_percentage: Mapped[float] = mapped_column(
        Float, nullable=False, server_default=text("100.0")
    )
    scopes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
    )

    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    verification_tokens: Mapped[List["VerificationToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        CheckConstraint("jsonb_typeof(scopes) = 'array'", name="ck_users_scopes_array"),
        CheckConstraint("jsonb_typeof(roles) = 'array'", name="ck_users_roles_array"),
        CheckConstraint("trust_score >= 0", name="ck_users_trust_score_positive"),
        CheckConstraint("reputation_percentage >= 0 AND reputation_percentage <= 100", name="ck_users_reputation_range"),
        Index("ix_users_email_lower", func.lower(email), unique=True),
        Index("ix_users_name_lower", func.lower(name), unique=True),
        Index("ix_users_trust_score", trust_score),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    jti: Mapped[str] = mapped_column(String(255), unique=True)
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    is_current: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("TRUE")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    user_agent: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")

    __table_args__ = (
        CheckConstraint("expires_at > issued_at", name="ck_refresh_tokens_expiry"),
        Index("ix_refresh_tokens_expires_at", expires_at),
        Index(
            "ix_refresh_tokens_active",
            expires_at,
            postgresql_where=revoked == text("FALSE"),
        ),
        Index(
            "ux_refresh_tokens_family_current",
            family_id,
            unique=True,
            postgresql_where=is_current == text("TRUE"),
        ),
    )


class VerificationToken(Base):
    __tablename__ = "verification_tokens"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    purpose: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'email_verification'")
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    user: Mapped["User"] = relationship(back_populates="verification_tokens")

    __table_args__ = (Index("ix_verification_tokens_expires_at", expires_at),)
