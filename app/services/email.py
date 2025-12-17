import aioboto3
from app.settings import settings


async def send_email(
    to_addr: str,
    subject: str,
    body: str,
) -> None:
    """Sends an email using AWS SES."""
    session = aioboto3.Session(region_name=settings.AWS_REGION)

    async with session.client("ses") as client:
        await client.send_email(
            Source=settings.MAIL_FROM,
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": body}},
            },
        )
