"""uppercase and regex constraints migration

Revision ID: 4f13e1e2ba81
Revises: 30d47b0b071b
Create Date: 2025-12-26 15:41:23.956390

This migration:
1. Updates content_reports.status server_default from 'pending' to 'PENDING'
2. Updates existing 'pending'/'approved'/'rejected' values to UPPERCASE
3. Recreates the unique index with UPPERCASE filter condition
4. Adds missing name regex constraint (ck_users_name_regex)
5. Adds missing email regex constraint (ck_users_email_regex)
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "4f13e1e2ba81"
down_revision: Union[str, Sequence[str], None] = "30d47b0b071b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1. Update existing status values to UPPERCASE
    op.execute(
        """
        UPDATE content_reports 
        SET status = UPPER(status) 
        WHERE status IN ('pending', 'approved', 'rejected')
    """
    )

    # 2. Alter column default from 'pending' to 'PENDING'
    op.alter_column("content_reports", "status", server_default=sa.text("'PENDING'"))

    # 3. Drop old unique index with lowercase filter
    op.drop_index(
        "ux_content_reports_unique_edit",
        table_name="content_reports",
        postgresql_where=sa.text("status IN ('pending', 'approved')"),
    )

    # 4. Recreate unique index with UPPERCASE filter
    op.create_index(
        "ux_content_reports_unique_edit",
        "content_reports",
        ["reporter_id", sa.literal_column("(target->>'edit_id')")],
        unique=True,
        postgresql_where=sa.text("status IN ('PENDING', 'APPROVED')"),
    )

    # 5. Add missing name regex constraint
    op.create_check_constraint(
        "ck_users_name_regex", "users", "name ~ '^[A-Za-z][A-Za-z0-9_\\.\\-]{1,29}$'"
    )

    # 6. Add missing email regex constraint
    op.create_check_constraint(
        "ck_users_email_regex",
        "users",
        "email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'",
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Drop regex constraints
    op.drop_constraint("ck_users_email_regex", "users", type_="check")
    op.drop_constraint("ck_users_name_regex", "users", type_="check")

    # Drop uppercase index
    op.drop_index(
        "ux_content_reports_unique_edit",
        table_name="content_reports",
        postgresql_where=sa.text("status IN ('PENDING', 'APPROVED')"),
    )

    # Recreate lowercase index
    op.create_index(
        "ux_content_reports_unique_edit",
        "content_reports",
        ["reporter_id", sa.literal_column("(target->>'edit_id')")],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'approved')"),
    )

    # Revert column default
    op.alter_column("content_reports", "status", server_default=sa.text("'pending'"))

    # Revert existing status values to lowercase
    op.execute(
        """
        UPDATE content_reports 
        SET status = LOWER(status) 
        WHERE status IN ('PENDING', 'APPROVED', 'REJECTED')
    """
    )
