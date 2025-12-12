"""Email-related tasks."""
import asyncio
from app.celery_app import app
from app.services.email import send_email


@app.task(name="tasks.email.send_verify_email")
def send_verify_email(to: str, subject: str, body: str) -> dict:
    try:
        asyncio.run(send_email(to_addr=to, subject=subject, body=body))
        return {"status": "sent", "to": to}
    except Exception as exc:
        # log and let Celery retry/backoff if configured
        app.log.get_default_logger().warning("email send failed: %s", exc)
        raise
