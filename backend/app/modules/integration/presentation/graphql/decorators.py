"""GraphQL decorators for Integration module.

This module provides decorators for GraphQL resolvers to handle
authentication, authorization, rate limiting, and other cross-cutting concerns.
"""

from collections.abc import Callable
from functools import wraps
from typing import Any
from uuid import UUID

from strawberry.types import Info

from app.core.exceptions import (
    ForbiddenException,
    RateLimitExceededException,
    ValidationException,
)

from .context import IntegrationContext


def integration_required(f: Callable) -> Callable:
    """Decorator to require a valid integration context."""

    @wraps(f)
    async def wrapper(
        self, info: Info[IntegrationContext, Any], integration_id: UUID, *args, **kwargs
    ):
        context = info.context

        # Check if user can access this integration
        if not await context.can_access_integration(integration_id):
            raise ForbiddenException("Access denied to integration")

        # Set current integration context
        context.set_current_integration(integration_id)

        # Check if integration exists and is active
        integration = await context.get_current_integration()
        if not integration:
            raise ValidationException("Integration not found")

        if not integration.is_active:
            raise ValidationException("Integration is not active")

        return await f(self, info, integration_id, *args, **kwargs)

    return wrapper


def health_check_required(f: Callable) -> Callable:
    """Decorator to require health check permissions."""

    @wraps(f)
    async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
        context = info.context

        if not context.can_view_health():
            raise ForbiddenException(
                "Insufficient permissions to view health information"
            )

        return await f(self, info, *args, **kwargs)

    return wrapper


def rate_limit_check(
    requests_per_hour: int = 100, key_func: Callable | None = None
) -> Callable:
    """Decorator to apply rate limiting to GraphQL resolvers."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
            context = info.context

            # Generate rate limit key
            if key_func:
                rate_limit_key = key_func(context, *args, **kwargs)
            else:
                user_id = (
                    context.current_user.id if context.current_user else "anonymous"
                )
                rate_limit_key = f"integration:{user_id}:{f.__name__}"

            # Check rate limit
            if not context.check_rate_limit(rate_limit_key, requests_per_hour, 3600):
                rate_info = context.get_rate_limit_info(rate_limit_key)
                raise RateLimitExceededException(
                    f"Rate limit exceeded. Try again in {rate_info['reset_time']} seconds."
                )

            return await f(self, info, *args, **kwargs)

        return wrapper

    return decorator


def admin_required(f: Callable) -> Callable:
    """Decorator to require admin permissions."""

    @wraps(f)
    async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
        context = info.context

        if not context.is_admin():
            raise ForbiddenException("Admin permissions required")

        return await f(self, info, *args, **kwargs)

    return wrapper


def permission_required(permission: str) -> Callable:
    """Decorator to require specific permissions."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
            context = info.context

            if not context.has_permission(permission):
                raise ForbiddenException(f"Permission '{permission}' required")

            return await f(self, info, *args, **kwargs)

        return wrapper

    return decorator


def webhook_management_required(f: Callable) -> Callable:
    """Decorator to require webhook management permissions."""

    @wraps(f)
    async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
        context = info.context

        if not context.can_manage_webhooks():
            raise ForbiddenException("Insufficient permissions to manage webhooks")

        return await f(self, info, *args, **kwargs)

    return wrapper


def sync_permission_required(f: Callable) -> Callable:
    """Decorator to require data synchronization permissions."""

    @wraps(f)
    async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
        context = info.context

        if not context.can_sync_data():
            raise ForbiddenException(
                "Insufficient permissions to perform data synchronization"
            )

        return await f(self, info, *args, **kwargs)

    return wrapper


def integration_health_check(f: Callable) -> Callable:
    """Decorator to check integration health before operations."""

    @wraps(f)
    async def wrapper(
        self, info: Info[IntegrationContext, Any], integration_id: UUID, *args, **kwargs
    ):
        context = info.context

        # Get integration
        integration = await context.integration_service.get_integration(integration_id)
        if not integration:
            raise ValidationException("Integration not found")

        # Check if integration is healthy
        if not integration.is_healthy:
            raise ValidationException(
                "Integration is not healthy. Please check the health status."
            )

        return await f(self, info, integration_id, *args, **kwargs)

    return wrapper


def log_operation(operation_name: str) -> Callable:
    """Decorator to log GraphQL operations."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def wrapper(self, info: Info[IntegrationContext, Any], *args, **kwargs):
            context = info.context

            # Log the operation
            import logging

            logger = logging.getLogger(__name__)

            user_id = context.current_user.id if context.current_user else "anonymous"
            logger.info(f"Integration operation: {operation_name} by user {user_id}")

            try:
                result = await f(self, info, *args, **kwargs)
                logger.info(f"Integration operation completed: {operation_name}")
                return result
            except Exception as e:
                logger.exception(
                    f"Integration operation failed: {operation_name} - {e!s}"
                )
                raise

        return wrapper

    return decorator


def validate_integration_type(allowed_types: list) -> Callable:
    """Decorator to validate integration type."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def wrapper(
            self,
            info: Info[IntegrationContext, Any],
            integration_id: UUID,
            *args,
            **kwargs,
        ):
            context = info.context

            # Get integration
            integration = await context.integration_service.get_integration(
                integration_id
            )
            if not integration:
                raise ValidationException("Integration not found")

            # Check integration type
            if integration.integration_type not in allowed_types:
                raise ValidationException(
                    f"Operation not supported for integration type: {integration.integration_type}"
                )

            return await f(self, info, integration_id, *args, **kwargs)

        return wrapper

    return decorator
