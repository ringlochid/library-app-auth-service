"""
Celery tasks package.
Import all task modules so they're registered with Celery.
"""
from app.tasks import email, media, roles, cleanup

__all__ = ["email", "media", "roles", "cleanup"]
