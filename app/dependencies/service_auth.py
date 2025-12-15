"""
Dependencies for service-to-service authentication.
"""

from fastapi import Header, HTTPException, status

from app.settings import settings


async def verify_service_token(x_service_token: str | None = Header(None)) -> None:
    """
    Verify service-to-service authentication token.

    Validates the X-Service-Token header matches the configured SERVICE_API_KEY.
    This is used for endpoints that should only be called by other services
    (e.g., Library Service calling trust adjustment endpoints).

    Args:
        x_service_token: Service authentication token from header

    Raises:
        HTTPException: 401 if token is missing or invalid
    """
    if not settings.SERVICE_API_KEY:
        # Service auth not configured - allow for development
        return

    if not x_service_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Service authentication required. Provide X-Service-Token header.",
        )

    if x_service_token != settings.SERVICE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service authentication token",
        )
