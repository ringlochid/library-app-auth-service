"""
Periodic cleanup tasks for database maintenance.
"""

# TODO: Beat is not working, still tracking log in cloudwatch

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select, delete

from app.celery_app import app
from app.database import create_worker_session
from app.models import User
from app.settings import settings

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@app.task(name="app.tasks.cleanup.delete_expired_unverified_users")
def delete_expired_unverified_users():
    """
    Delete users who haven't verified their email before expires_at.

    This task runs periodically (recommended: daily) to clean up:
    - Users where expires_at <= now()
    - AND email_verified_at IS NULL

    Verified users have expires_at set to NULL, so they won't be deleted.
    """

    async def _cleanup():
        # Create fresh async session for this task
        WorkerSession, engine = create_worker_session()

        try:
            async with WorkerSession() as session:
                now = _now_utc()

                stmt = select(User).where(
                    User.expires_at <= now, User.email_verified_at.is_(None)
                )
                result = await session.execute(stmt)
                expired_users = result.scalars().all()

                if not expired_users:
                    logger.info("No expired unverified users found")
                    return 0

                user_ids = [str(user.id) for user in expired_users]
                user_emails = [user.email for user in expired_users]
                logger.info(
                    f"Deleting {len(expired_users)} expired unverified users: {user_emails}"
                )

                delete_stmt = delete(User).where(
                    User.expires_at <= now, User.email_verified_at.is_(None)
                )
                result = await session.execute(delete_stmt)
                await session.commit()

                deleted_count = result.rowcount  # type: ignore[attr-defined]
                logger.info(
                    f"Successfully deleted {deleted_count} expired unverified users"
                )
                return deleted_count

        finally:
            await engine.dispose()

    # Run the async cleanup
    return asyncio.run(_cleanup())
