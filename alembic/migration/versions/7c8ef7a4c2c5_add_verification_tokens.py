"""add verification tokens table

Revision ID: 7c8ef7a4c2c5
Revises: 19a62ead1ddb
Create Date: 2025-12-12 00:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7c8ef7a4c2c5"
down_revision: Union[str, Sequence[str], None] = "19a62ead1ddb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "verification_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "purpose",
            sa.String(length=64),
            server_default=sa.text("'email_verification'"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_verification_tokens_expires_at",
        "verification_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_verification_tokens_user_id",
        "verification_tokens",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_verification_tokens_user_id", table_name="verification_tokens")
    op.drop_index("ix_verification_tokens_expires_at", table_name="verification_tokens")
    op.drop_table("verification_tokens")
