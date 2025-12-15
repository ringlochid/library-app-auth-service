"""
Role-based access control dependencies.
"""

from typing import Callable
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession


from app.models import User
from app.security import get_current_user_with_access_token
from app.database import get_db


def require_roles(allowed_roles: list[str]) -> Callable:
    """
    Create a dependency that requires user to have one of the specified roles.

    Args:
        allowed_roles: List of roles that are allowed (e.g., ["admin", "curator"])

    Returns:
        Dependency function that checks user roles

    Example:
        @router.get("/admin-only")
        async def admin_endpoint(
            current_user: User = Depends(require_roles(["admin"]))
        ):
            ...
    """

    async def role_checker(
        current_user: User = Depends(get_current_user_with_access_token),
    ) -> User:
        """Check if user has required role."""
        user_roles = current_user.roles or []

        if not any(role in user_roles for role in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {', '.join(allowed_roles)}",
            )

        return current_user

    return role_checker
