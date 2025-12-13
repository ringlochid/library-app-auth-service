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
    msg["From"] = mail_from or settings.MAIL_FROM or "no-reply@example.com"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    host = host or settings.MAIL_HOST
    port = port or settings.MAIL_PORT
    user = username or settings.MAIL_USER
    pwd = password or settings.MAIL_PASSWORD

    await aiosmtplib.send(
        msg,
        hostname=host,
        port=port,
        username=user,
        password=pwd,
        start_tls=start_tls,
    )
