import pytest
from unittest.mock import AsyncMock, patch
from app.services.email import send_email
from app.settings import settings


@pytest.mark.asyncio
@patch("app.services.email.aioboto3")
async def test_send_email_ses_mocked(mock_aioboto3):
    """
    Tests that the send_email service correctly calls the aioboto3 SES client.
    """
    # Configure the mock session and client
    mock_session = mock_aioboto3.Session.return_value
    mock_ses_client = AsyncMock()
    mock_session.client.return_value.__aenter__.return_value = mock_ses_client

    # Define test data
    to_addr = "test@example.com"
    subject = "Test Email"
    body = "<h1>Hello World</h1>"

    # Call the function
    await send_email(to_addr=to_addr, subject=subject, body=body)

    # Assert that a session was created with the correct region
    mock_aioboto3.Session.assert_called_with(region_name=settings.AWS_REGION)

    # Assert that the client was created
    mock_session.client.assert_called_with("ses")

    # Assert that send_email was called with the correct parameters
    mock_ses_client.send_email.assert_called_once_with(
        Source=settings.MAIL_FROM,
        Destination={"ToAddresses": [to_addr]},
        Message={
            "Subject": {"Data": subject},
            "Body": {"Html": {"Data": body}},
        },
    )
