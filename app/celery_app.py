from celery import Celery
from app.settings import settings

# Prefer configured settings (loaded from .env) with env fallback for flexibility.
broker_url = (
    settings.CELERY_BROKER_URL or settings.REDIS_URL or "redis://localhost:6379/0"
)

backend_url = settings.CELERY_RESULT_BACKEND or "redis://localhost:6379/1"

app = Celery("openshelves_auth", broker=broker_url, backend=backend_url)


app.conf.update(
    task_default_queue=settings.CELERY_TASK_DEFAULT_QUEUE or "default",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=settings.CELERY_TIMEZONE or "UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_routes={
        "app.tasks.media.*": {"queue": "media"},
        "app.tasks.email.*": {"queue": "email"},
        "app.tasks.roles.*": {"queue": "default"},
        "app.tasks.cleanup.*": {"queue": "default"},
    },
    # Celery Beat schedule for periodic tasks
    beat_schedule={
        "cleanup-expired-users-daily": {
            "task": "app.tasks.cleanup.delete_expired_unverified_users",
            "schedule": 86400.0,  # Run every 24 hours (in seconds)
            # To run at specific time, use crontab:
            # "schedule": crontab(hour=2, minute=0),  # Run at 2:00 AM daily
        },
    },
)

# Ensure tasks under app.tasks.* are registered
app.autodiscover_tasks(["app.tasks"])
