"""add email_verified_at

Revision ID: 2fd4c5c0f3cf
Revises: 7c8ef7a4c2c5
Create Date: 2025-12-12 01:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2fd4c5c0f3cf"
down_revision: Union[str, Sequence[str], None] = "7c8ef7a4c2c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "email_verified_at")
