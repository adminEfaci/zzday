"""
GraphQL Authorization System

Provides decorators and utilities for implementing authorization in GraphQL resolvers.
Supports field-level permissions, role-based access control, and custom authorization logic.
"""

import asyncio
import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from strawberry import GraphQLError
from strawberry.types import Info

logger = logging.getLogger(__name__)


class AuthorizationError(GraphQLError):
    """Custom error for authorization failures"""
    
    def __init__(
        self, 
        message: str = "Unauthorized", 
        code: str = "FORBIDDEN",
        required_permission: str | None = None
    ):
        super().__init__(
            message,
            extensions={
                "code": code,
                "required_permission": required_permission
            }
        )


# ============================================================================
# Authorization Decorators
# ============================================================================

def requires_auth(func: Callable) -> Callable:
    """
    Decorator that requires the user to be authenticated.
    
    Usage:
        @strawberry.field
        @requires_auth
        async def me(self, info: Info) -> User:
            # User is guaranteed to be authenticated
            return info.context["user"]
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Find the Info object
        info = _find_info_object(args, kwargs)
        if not info:
            raise RuntimeError("No Info object found in resolver arguments")
        
        # Check authentication
        user = info.context.get("user")
        is_authenticated = info.context.get("is_authenticated", False)
        
        if not is_authenticated or not user:
            logger.warning(f"Unauthenticated access attempt to {func.__name__}")
            raise AuthorizationError(
                "Authentication required",
                code="UNAUTHENTICATED"
            )
        
        # Call the original function
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        return func(*args, **kwargs)
    
    return wrapper


def requires_permission(permission: str):
    """
    Decorator that requires a specific permission.
    
    Usage:
        @strawberry.field
        @requires_permission("users:read")
        async def users(self, info: Info) -> List[User]:
            # User has the required permission
            return await get_users()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Info object
            info = _find_info_object(args, kwargs)
            if not info:
                raise RuntimeError("No Info object found in resolver arguments")
            
            # First check authentication
            user = info.context.get("user")
            if not user:
                raise AuthorizationError(
                    "Authentication required",
                    code="UNAUTHENTICATED"
                )
            
            # Check permission
            if not await _check_user_permission(info, user, permission):
                logger.warning(
                    f"Permission denied for user {user.id} accessing {func.__name__} "
                    f"(required: {permission})"
                )
                raise AuthorizationError(
                    f"Permission '{permission}' required",
                    code="FORBIDDEN",
                    required_permission=permission
                )
            
            # Call the original function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def requires_any_permission(*permissions: str):
    """
    Decorator that requires at least one of the specified permissions.
    
    Usage:
        @strawberry.field
        @requires_any_permission("users:read", "users:admin")
        async def users(self, info: Info) -> List[User]:
            # User has at least one of the required permissions
            return await get_users()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Info object
            info = _find_info_object(args, kwargs)
            if not info:
                raise RuntimeError("No Info object found in resolver arguments")
            
            # First check authentication
            user = info.context.get("user")
            if not user:
                raise AuthorizationError(
                    "Authentication required",
                    code="UNAUTHENTICATED"
                )
            
            # Check if user has any of the permissions
            has_permission = False
            for permission in permissions:
                if await _check_user_permission(info, user, permission):
                    has_permission = True
                    break
            
            if not has_permission:
                logger.warning(
                    f"Permission denied for user {user.id} accessing {func.__name__} "
                    f"(required any of: {', '.join(permissions)})"
                )
                raise AuthorizationError(
                    f"One of these permissions required: {', '.join(permissions)}",
                    code="FORBIDDEN"
                )
            
            # Call the original function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def requires_all_permissions(*permissions: str):
    """
    Decorator that requires all of the specified permissions.
    
    Usage:
        @strawberry.field
        @requires_all_permissions("users:read", "users:write")
        async def update_users(self, info: Info) -> List[User]:
            # User has all required permissions
            return await update_users()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Info object
            info = _find_info_object(args, kwargs)
            if not info:
                raise RuntimeError("No Info object found in resolver arguments")
            
            # First check authentication
            user = info.context.get("user")
            if not user:
                raise AuthorizationError(
                    "Authentication required",
                    code="UNAUTHENTICATED"
                )
            
            # Check if user has all permissions
            missing_permissions = []
            for permission in permissions:
                if not await _check_user_permission(info, user, permission):
                    missing_permissions.append(permission)
            
            if missing_permissions:
                logger.warning(
                    f"Permission denied for user {user.id} accessing {func.__name__} "
                    f"(missing: {', '.join(missing_permissions)})"
                )
                raise AuthorizationError(
                    f"All permissions required: {', '.join(permissions)}",
                    code="FORBIDDEN"
                )
            
            # Call the original function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def requires_role(role: str):
    """
    Decorator that requires a specific role.
    
    Usage:
        @strawberry.field
        @requires_role("admin")
        async def admin_panel(self, info: Info) -> AdminData:
            # User has admin role
            return await get_admin_data()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Info object
            info = _find_info_object(args, kwargs)
            if not info:
                raise RuntimeError("No Info object found in resolver arguments")
            
            # First check authentication
            user = info.context.get("user")
            if not user:
                raise AuthorizationError(
                    "Authentication required",
                    code="UNAUTHENTICATED"
                )
            
            # Check role
            if not await _check_user_role(info, user, role):
                logger.warning(
                    f"Role denied for user {user.id} accessing {func.__name__} "
                    f"(required: {role})"
                )
                raise AuthorizationError(
                    f"Role '{role}' required",
                    code="FORBIDDEN"
                )
            
            # Call the original function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def public(func: Callable) -> Callable:
    """
    Decorator that explicitly marks a resolver as public (no auth required).
    This is useful for documentation and clarity.
    
    Usage:
        @strawberry.field
        @public
        async def health_check(self, info: Info) -> str:
            return "OK"
    """
    # Just return the function as-is, but mark it
    func._is_public = True
    return func


# ============================================================================
# Field-Level Authorization
# ============================================================================

def authorize_field(
    permission: str | None = None,
    condition: Callable | None = None,
    default_value: Any = None
):
    """
    Decorator for field-level authorization.
    
    Args:
        permission: Required permission to access this field
        condition: Custom condition function(user, obj) -> bool
        default_value: Value to return if unauthorized
    
    Usage:
        @strawberry.type
        class User:
            id: str
            email: str
            
            @strawberry.field
            @authorize_field(permission="users:read:sensitive")
            async def ssn(self) -> Optional[str]:
                return self._ssn
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, info: Info, *args, **kwargs):
            user = info.context.get("user")
            
            # Check permission if specified
            if permission and not await _check_user_permission(info, user, permission):
                logger.debug(
                    f"Field authorization denied for {func.__name__} "
                    f"(permission: {permission})"
                )
                return default_value
            
            # Check custom condition if specified
            if condition and not condition(user, self):
                logger.debug(
                    f"Field authorization denied for {func.__name__} "
                    f"(custom condition)"
                )
                return default_value
            
            # Call the original function
            if asyncio.iscoroutinefunction(func):
                return await func(self, info, *args, **kwargs)
            return func(self, info, *args, **kwargs)
        
        return wrapper
    return decorator


# ============================================================================
# Authorization Context Manager
# ============================================================================

class AuthorizationContext:
    """
    Context manager for handling authorization in a batch of operations.
    
    Usage:
        async with AuthorizationContext(info) as auth:
            if await auth.has_permission("users:read"):
                users = await get_users()
            if await auth.has_role("admin"):
                admin_data = await get_admin_data()
    """
    
    def __init__(self, info: Info):
        self.info = info
        self.user = info.context.get("user")
        self._permission_cache: dict[str, bool] = {}
        self._role_cache: dict[str, bool] = {}
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Clear caches
        self._permission_cache.clear()
        self._role_cache.clear()
    
    async def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission (cached)"""
        if not self.user:
            return False
        
        if permission not in self._permission_cache:
            self._permission_cache[permission] = await _check_user_permission(
                self.info, self.user, permission
            )
        
        return self._permission_cache[permission]
    
    async def has_any_permission(self, *permissions: str) -> bool:
        """Check if user has any of the specified permissions"""
        for permission in permissions:
            if await self.has_permission(permission):
                return True
        return False
    
    async def has_all_permissions(self, *permissions: str) -> bool:
        """Check if user has all of the specified permissions"""
        for permission in permissions:
            if not await self.has_permission(permission):
                return False
        return True
    
    async def has_role(self, role: str) -> bool:
        """Check if user has a specific role (cached)"""
        if not self.user:
            return False
        
        if role not in self._role_cache:
            self._role_cache[role] = await _check_user_role(
                self.info, self.user, role
            )
        
        return self._role_cache[role]
    
    def require_auth(self):
        """Require authentication or raise error"""
        if not self.user:
            raise AuthorizationError(
                "Authentication required",
                code="UNAUTHENTICATED"
            )
    
    async def require_permission(self, permission: str):
        """Require permission or raise error"""
        self.require_auth()
        if not await self.has_permission(permission):
            raise AuthorizationError(
                f"Permission '{permission}' required",
                code="FORBIDDEN",
                required_permission=permission
            )


# ============================================================================
# Helper Functions
# ============================================================================

def _find_info_object(args: tuple, kwargs: dict) -> Info | None:
    """Find the Info object in resolver arguments"""
    # Check positional arguments
    for arg in args:
        if isinstance(arg, Info):
            return arg
    
    # Check keyword arguments
    for arg in kwargs.values():
        if isinstance(arg, Info):
            return arg
    
    return None


async def _check_user_permission(info: Info, user: Any, permission: str) -> bool:
    """
    Check if a user has a specific permission.
    
    This function should be customized based on your permission system.
    """
    if not user:
        return False
    
    # Get the container to access services
    container = info.context.get("container")
    if not container:
        logger.error("No DI container in context")
        return False
    
    try:
        # Get the authorization service
        from app.modules.identity.application.services.authorization_service import (
            AuthorizationService,
        )
        auth_service = container.resolve(AuthorizationService)
        
        # Check permission
        return await auth_service.user_has_permission(user.id, permission)
    except Exception:
        logger.exception("Error checking permission")
        return False


async def _check_user_role(info: Info, user: Any, role: str) -> bool:
    """
    Check if a user has a specific role.
    
    This function should be customized based on your role system.
    """
    if not user:
        return False
    
    # Get the container to access services
    container = info.context.get("container")
    if not container:
        logger.error("No DI container in context")
        return False
    
    try:
        # Get the authorization service
        from app.modules.identity.application.services.authorization_service import (
            AuthorizationService,
        )
        auth_service = container.resolve(AuthorizationService)
        
        # Check role
        return await auth_service.user_has_role(user.id, role)
    except Exception:
        logger.exception("Error checking role")
        return False


__all__ = [
    # Context
    "AuthorizationContext",
    # Error
    "AuthorizationError",
    # Decorators
    "authorize_field",
    "public",
    "requires_all_permissions",
    "requires_any_permission",
    "requires_auth",
    "requires_permission",
    "requires_role",
]