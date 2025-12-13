import time

import pytest

from app.services.email import send_email
from app.settings import settings


mail_host = settings.MAIL_HOST
mail_user = settings.MAIL_USER
mail_password = settings.MAIL_PASSWORD
mail_from = settings.MAIL_FROM
mail_to = settings.MAIL_TEST_TO or settings.MAIL_TO


skip_reason = (
    "Mailtrap/SMTP env vars not set; set MAIL_HOST, MAIL_USER, MAIL_PASSWORD, "
    "MAIL_FROM, and MAIL_TEST_TO (or MAIL_TO) to run integration test."
)
skip_mark = pytest.mark.skipif(
    not (mail_host and mail_user and mail_password and mail_from and mail_to),
    reason=skip_reason,
)


@skip_mark
@pytest.mark.asyncio
@pytest.mark.integration
async def test_send_email_integration_mailtrap():
    """
    Integration test that sends a real email via configured SMTP (e.g., Mailtrap).

    This test is skipped unless the required env vars are set:
    MAIL_HOST, MAIL_USER, MAIL_PASSWORD, MAIL_FROM, and MAIL_TEST_TO (or MAIL_TO).
    """
    subject = f"Auth service integration test {int(time.time())}"
    body = "Integration test from auth service."

    await send_email(
        to_addr=mail_to,
        subject=subject,
        body=body,
        mail_from=mail_from,
        host=mail_host,
        username=mail_user,
        password=mail_password,
    )
