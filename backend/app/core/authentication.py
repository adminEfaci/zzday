"""
Core Authentication Module for EzzDay

This module provides authentication decorators and utilities for GraphQL resolvers
and other application components. It serves as a bridge between the core authentication
middleware and application-level authentication requirements.

This module exports the authentication decorators and utilities referenced in
AGENT_CONTRACTS.md and used throughout the application.
"""

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

try:
    from strawberry.types import Info

    _HAS_STRAWBERRY = True
except ImportError:
    _HAS_STRAWBERRY = False

from app.core.errors import PermissionDeniedError, UnauthorizedError
from app.core.logging import get_logger

try:
    from app.core.middleware.auth import (
        AuthorizationContext,
        CoreAuthenticator,
        PermissionChecker,
        get_auth_context,
        get_current_user_id,
    )
except ImportError:
    # Create minimal fallback implementations
    from dataclasses import dataclass
    from uuid import UUID
    
    @dataclass
    class AuthorizationContext:
        user_id: UUID
        permissions: list[str]
        roles: list[str]
        session_id: str | None = None
    
    # PermissionDeniedError is now imported from core.errors
    
    class CoreAuthenticator:
        pass
    
    class PermissionChecker:
        async def check_permission(self, **kwargs: Any) -> bool:
            return True
    
    def get_auth_context(request: Any) -> AuthorizationContext | None:
        return None
    
    def get_current_user_id(request: Any) -> UUID | None:
        return None

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def require_auth() -> Callable[[F], F]:
    """
    Decorator to require authentication for GraphQL resolvers and other functions.

    This decorator ensures that the current request has valid authentication.
    It works with both GraphQL resolvers (using strawberry.Info) and regular
    functions that have access to request context.

    Usage:
        @strawberry.field
        @require_auth()
        async def protected_field(self, info: Info) -> str:
            return "Protected data"

    Raises:
        UnauthorizedError: If user is not authenticated
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract info parameter (should be strawberry.Info for GraphQL resolvers)
            info = None
            for arg in args:
                if _HAS_STRAWBERRY and isinstance(arg, Info):
                    info = arg
                    break

            if not info:
                # Look for info in kwargs
                info = kwargs.get("info")

            if info and hasattr(info, "context") and hasattr(info.context, "get"):
                # GraphQL resolver context
                request = info.context.get("request")
                if request:
                    user_id = get_current_user_id(request)
                    if not user_id:
                        logger.warning(
                            "Authentication required but not provided",
                            resolver=func.__name__,
                            path=getattr(request, "url", {}).path
                            if hasattr(request, "url")
                            else None,
                        )
                        raise UnauthorizedError("Authentication required")
                else:
                    logger.error(
                        "No request context available for authentication",
                        resolver=func.__name__,
                    )
                    raise UnauthorizedError("Authentication context unavailable")
            else:
                logger.error(
                    "Invalid context for authentication decorator",
                    function=func.__name__,
                )
                raise UnauthorizedError("Authentication context unavailable")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_permission(
    resource: str, action: str = "read", scope: str = "all"
) -> Callable[[F], F]:
    """
    Decorator to require specific permissions for GraphQL resolvers and functions.

    This decorator ensures that the authenticated user has the required permission
    to access the protected resource. It follows the permission format:
    "resource:action:scope"

    Args:
        resource: Resource type (e.g., "users", "documents", "settings")
        action: Action to perform (e.g., "read", "write", "delete")
        scope: Permission scope (e.g., "own", "department", "organization", "all")

    Usage:
        @strawberry.field
        @require_auth()
        @require_permission("users", "write", "department")
        async def update_user(self, info: Info, user_id: str) -> User:
            # User has permission to write users in their department
            return await user_service.update(user_id)

    Raises:
        UnauthorizedError: If user is not authenticated
        PermissionDeniedError: If user lacks required permission
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract info parameter
            info = None
            for arg in args:
                if _HAS_STRAWBERRY and isinstance(arg, Info):
                    info = arg
                    break

            if not info:
                info = kwargs.get("info")

            if info and hasattr(info, "context") and hasattr(info.context, "get"):
                request = info.context.get("request")
                if request:
                    # Ensure user is authenticated first
                    auth_context = get_auth_context(request)
                    if not auth_context:
                        logger.warning(
                            "Permission check requires authentication",
                            resolver=func.__name__,
                            permission=f"{resource}:{action}:{scope}",
                        )
                        raise UnauthorizedError("Authentication required")

                    # Check permission
                    permission_checker = PermissionChecker()
                    has_permission = await permission_checker.check_permission(
                        auth_context=auth_context,
                        resource=resource,
                        action=action,
                        scope=scope,
                    )

                    if not has_permission:
                        logger.warning(
                            "Permission denied",
                            user_id=str(auth_context.user_id),
                            resolver=func.__name__,
                            permission=f"{resource}:{action}:{scope}",
                            user_permissions=auth_context.permissions,
                        )
                        raise PermissionDeniedError(
                            f"Permission denied: {resource}:{action}:{scope}"
                        )

                    logger.debug(
                        "Permission granted",
                        user_id=str(auth_context.user_id),
                        resolver=func.__name__,
                        permission=f"{resource}:{action}:{scope}",
                    )
                else:
                    logger.error(
                        "No request context available for permission check",
                        resolver=func.__name__,
                    )
                    raise UnauthorizedError("Authentication context unavailable")
            else:
                logger.error(
                    "Invalid context for permission decorator", function=func.__name__
                )
                raise UnauthorizedError("Authentication context unavailable")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def get_current_user(info: Any | None = None, request: Any | None = None) -> str | None:
    """
    Get the current authenticated user ID from GraphQL info or request context.

    Args:
        info: Strawberry GraphQL info object
        request: FastAPI request object

    Returns:
        User ID string if authenticated, None otherwise
    """
    if info and hasattr(info, "context") and hasattr(info.context, "get"):
        request = info.context.get("request")

    if request:
        user_id = get_current_user_id(request)
        return str(user_id) if user_id else None

    return None


def get_current_auth_context(
    info: Any | None = None, request: Any | None = None
) -> AuthorizationContext | None:
    """
    Get the current authorization context from GraphQL info or request context.

    Args:
        info: Strawberry GraphQL info object
        request: FastAPI request object

    Returns:
        AuthorizationContext if authenticated, None otherwise
    """
    if info and hasattr(info, "context") and hasattr(info.context, "get"):
        request = info.context.get("request")

    if request:
        return get_auth_context(request)

    return None


async def check_permission(
    info: Any,
    resource: str,
    action: str = "read",
    scope: str = "all",
    resource_context: dict[str, Any] | None = None,
) -> bool:
    """
    Check if the current user has a specific permission.

    Args:
        info: Strawberry GraphQL info object
        resource: Resource type
        action: Action to perform
        scope: Permission scope
        resource_context: Additional context for permission evaluation

    Returns:
        True if permission is granted, False otherwise

    Raises:
        UnauthorizedError: If user is not authenticated
    """
    auth_context = get_current_auth_context(info=info)
    if not auth_context:
        raise UnauthorizedError("Authentication required")

    permission_checker = PermissionChecker()
    return await permission_checker.check_permission(
        auth_context=auth_context,
        resource=resource,
        action=action,
        scope=scope,
        resource_context=resource_context,
    )


# Re-export for convenience
__all__ = [
    "AuthorizationContext",
    "CoreAuthenticator",
    "PermissionChecker",
    "PermissionDeniedError",
    "UnauthorizedError",
    "check_permission",
    "get_current_auth_context",
    "get_current_user",
    "require_auth",
    "require_permission",
]
