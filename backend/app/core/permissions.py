from collections.abc import Sequence

from fastapi import Depends, HTTPException, status

from backend.app.core.dependencies import get_current_active_user
from backend.app.models.user import User, UserRole


class RoleChecker:
    """Dependency that checks if the authenticated user has any of the specified roles."""

    def __init__(self, allowed_roles: Sequence[UserRole | str]) -> None:
        self.allowed_roles = [
            r.value if isinstance(r, UserRole) else str(r) for r in allowed_roles
        ]

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required role: {', '.join(self.allowed_roles)}"
            )
        return current_user


# Predefined permission dependencies
require_admin = RoleChecker([UserRole.ADMIN])
require_analyst = RoleChecker([UserRole.ADMIN, UserRole.ANALYST])
require_authenticated = get_current_active_user
