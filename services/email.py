import os
from email.message import EmailMessage
from typing import Optional

import aiosmtplib

from app.settings import settings


async def send_email(
    to_addr: str,
    subject: str,
    body: str,
    *,
    mail_from: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    start_tls: bool = True,
) -> None:
    """Send a plain text email using SMTP settings from env/settings."""
    msg = EmailMessage()
    msg["From"] = mail_from or getattr(settings, "MAIL_FROM", "no-reply@example.com")
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    await aiosmtplib.send(
        msg,
        hostname=host or os.getenv("MAIL_HOST") or getattr(settings, "MAIL_HOST", None),
        port=port or int(os.getenv("MAIL_PORT", "587")),
        username=username
        or os.getenv("MAIL_USER")
        or getattr(settings, "MAIL_USER", None),
        password=password
        or os.getenv("MAIL_PASSWORD")
        or getattr(settings, "MAIL_PASSWORD", None),
        start_tls=start_tls,
    )
