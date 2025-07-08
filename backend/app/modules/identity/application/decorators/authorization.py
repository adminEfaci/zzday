"""
Authorization decorators for command and query handlers.

Provides authorization checks as decorators.
"""

from collections.abc import Callable
from functools import wraps

from app.core.cqrs import Command, Query
from app.modules.identity.application.services import get_authorization_service
from app.modules.identity.domain.errors import ForbiddenError, UnauthorizedError


def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication.
    
    Checks that the command/query has a valid user_id or current_user_id.
    """
    @wraps(func)
    async def wrapper(self, request: Command | Query, *args, **kwargs):
        # Check for user_id in various possible attribute names
        user_id = None
        for attr in ['user_id', 'current_user_id', 'actor_id', 'requestor_id']:
            if hasattr(request, attr):
                user_id = getattr(request, attr)
                break
        
        if not user_id:
            raise UnauthorizedError("Authentication required")
        
        # Could add additional checks here like checking if user exists
        # or if session is valid
        
        return await func(self, request, *args, **kwargs)
    
    return wrapper


def require_permission(
    permission: str,
    resource_type: str | None = None,
    resource_id_attr: str | None = None
) -> Callable:
    """
    Decorator to require specific permission.
    
    Args:
        permission: Permission name to check
        resource_type: Type of resource being accessed
        resource_id_attr: Attribute name in request containing resource ID
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get user ID
            user_id = None
            for attr in ['user_id', 'current_user_id', 'actor_id', 'requestor_id']:
                if hasattr(request, attr):
                    user_id = getattr(request, attr)
                    break
            
            if not user_id:
                raise UnauthorizedError("Authentication required")
            
            # Get resource ID if specified
            resource_id = None
            if resource_id_attr and hasattr(request, resource_id_attr):
                resource_id = str(getattr(request, resource_id_attr))
            
            # Build authorization context
            from app.modules.identity.domain.specifications import (
                authorization_specifications,
            )
            AuthorizationContext = (
                authorization_specifications.AuthorizationContext
            )
            context = AuthorizationContext(
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=permission
            )
            
            # Check permission
            auth_service = get_authorization_service()
            result = await auth_service.check_permission(context, permission)
            
            if not result.allowed:
                raise ForbiddenError(
                    f"Permission denied: {result.reason}",
                    denial_code=result.denial_code
                )
            
            # Add permission check result to kwargs for handler use
            kwargs['permission_result'] = result
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_role(roles: str | list[str]) -> Callable:
    """
    Decorator to require one of specified roles.
    
    Args:
        roles: Single role or list of roles (user must have at least one)
    """
    if isinstance(roles, str):
        roles = [roles]
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get user ID
            user_id = None
            for attr in ['user_id', 'current_user_id', 'actor_id', 'requestor_id']:
                if hasattr(request, attr):
                    user_id = getattr(request, attr)
                    break
            
            if not user_id:
                raise UnauthorizedError("Authentication required")
            
            # Check if user has any of the required roles
            auth_service = get_authorization_service()
            user_roles = await auth_service.get_user_roles(user_id)
            user_role_names = [role.name for role in user_roles]
            
            if not any(role in user_role_names for role in roles):
                raise ForbiddenError(
                    f"Required role(s): {', '.join(roles)}. "
                    f"User roles: {', '.join(user_role_names)}"
                )
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_self_or_permission(
    user_id_attr: str = 'target_user_id',
    permission: str = 'admin_users'
) -> Callable:
    """
    Decorator to require either operating on self or having specific permission.
    
    Common pattern for user operations where users can modify their own data
    or admins can modify any user's data.
    
    Args:
        user_id_attr: Attribute name containing target user ID
        permission: Permission required if not operating on self
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get current user ID
            current_user_id = None
            for attr in ['current_user_id', 'actor_id', 'requestor_id']:
                if hasattr(request, attr):
                    current_user_id = getattr(request, attr)
                    break
            
            if not current_user_id:
                raise UnauthorizedError("Authentication required")
            
            # Get target user ID
            if not hasattr(request, user_id_attr):
                raise ValueError(f"Request missing required attribute: {user_id_attr}")
            
            target_user_id = getattr(request, user_id_attr)
            
            # Check if operating on self
            if current_user_id == target_user_id:
                return await func(self, request, *args, **kwargs)
            
            # Otherwise check permission
            from app.modules.identity.domain.specifications import (
                authorization_specifications,
            )
            AuthorizationContext = (
                authorization_specifications.AuthorizationContext
            )
            context = AuthorizationContext(
                user_id=current_user_id,
                resource_type='user',
                resource_id=str(target_user_id),
                action=permission
            )
            
            auth_service = get_authorization_service()
            result = await auth_service.check_permission(context, permission)
            
            if not result.allowed:
                raise ForbiddenError(
                    f"Cannot modify other users without {permission} permission"
                )
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_owner_or_permission(
    resource_type: str,
    resource_id_attr: str,
    owner_id_attr: str,
    permission: str
) -> Callable:
    """
    Decorator to require either being resource owner or having permission.
    
    Args:
        resource_type: Type of resource
        resource_id_attr: Attribute containing resource ID
        owner_id_attr: Attribute containing owner ID
        permission: Permission required if not owner
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get current user ID
            current_user_id = None
            for attr in ['current_user_id', 'actor_id', 'user_id']:
                if hasattr(request, attr):
                    current_user_id = getattr(request, attr)
                    break
            
            if not current_user_id:
                raise UnauthorizedError("Authentication required")
            
            # Get owner ID
            if not hasattr(request, owner_id_attr):
                # Try to fetch from repository
                resource_id = getattr(request, resource_id_attr)
                # This would need to be implemented based on resource type
                owner_id = await self._get_resource_owner(resource_type, resource_id)
            else:
                owner_id = getattr(request, owner_id_attr)
            
            # Check if user is owner
            if current_user_id == owner_id:
                return await func(self, request, *args, **kwargs)
            
            # Otherwise check permission
            from app.modules.identity.domain.specifications import (
                authorization_specifications,
            )
            AuthorizationContext = (
                authorization_specifications.AuthorizationContext
            )
            context = AuthorizationContext(
                user_id=current_user_id,
                resource_type=resource_type,
                resource_id=str(getattr(request, resource_id_attr)),
                action=permission
            )
            
            auth_service = get_authorization_service()
            result = await auth_service.check_permission(context, permission)
            
            if not result.allowed:
                raise ForbiddenError(
                    f"Must be owner or have {permission} permission"
                )
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_mfa(operation: str | None = None) -> Callable:
    """
    Decorator to require MFA verification for sensitive operations.
    
    Args:
        operation: Specific operation name for MFA check
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get user ID
            user_id = None
            for attr in ['user_id', 'current_user_id', 'actor_id']:
                if hasattr(request, attr):
                    user_id = getattr(request, attr)
                    break
            
            if not user_id:
                raise UnauthorizedError("Authentication required")
            
            # Check if MFA is verified for this session
            mfa_verified = getattr(request, 'mfa_verified', False)
            if hasattr(request, 'session_id'):
                # Could check session for MFA verification
                pass
            
            if not mfa_verified:
                from app.modules.identity.domain.errors import MFARequiredError
                raise MFARequiredError(
                    "MFA verification required for this operation",
                    operation=operation or func.__name__
                )
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator