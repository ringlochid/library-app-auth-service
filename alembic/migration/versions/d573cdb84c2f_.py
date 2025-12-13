"""empty message

Revision ID: d573cdb84c2f
Revises: 4af57f0759ed
Create Date: 2025-12-13 20:40:42.075925

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd573cdb84c2f'
down_revision: Union[str, Sequence[str], None] = '4af57f0759ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
