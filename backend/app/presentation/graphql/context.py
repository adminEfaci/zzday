"""
GraphQL Context Utilities

Provides utilities for accessing context in GraphQL resolvers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strawberry.types import Info

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.cache import CacheManager
    from app.core.dependencies import Container
    from app.core.events.types import IEventBus
    from app.presentation.graphql.dataloaders import DataLoaderRegistry


class GraphQLContext:
    """Helper class for accessing GraphQL context in resolvers."""

    def __init__(self, info: Info):
        """Initialize with Strawberry info object."""
        self.info = info
        self.context = info.context

    @property
    def request(self) -> Any:
        """Get the request object."""
        return self.context.get("request")

    @property
    def response(self) -> Any:
        """Get the response object."""
        return self.context.get("response")

    @property
    def user(self) -> Any | None:
        """Get the current authenticated user."""
        return self.context.get("user")

    @property
    def is_authenticated(self) -> bool:
        """Check if the user is authenticated."""
        return self.context.get("is_authenticated", False)

    @property
    def container(self) -> Container | None:
        """Get the dependency injection container."""
        return self.context.get("container")

    @property
    def event_bus(self) -> IEventBus | None:
        """Get the event bus instance."""
        return self.context.get("event_bus")

    @property
    def cache_manager(self) -> CacheManager | None:
        """Get the cache manager instance."""
        return self.context.get("cache_manager")
    
    @property
    def loaders(self) -> DataLoaderRegistry | None:
        """Get the dataloader registry."""
        return self.context.get("loaders")

    async def get_db_session(self) -> AsyncSession:
        """
        Get a database session.

        Returns:
            AsyncSession: Database session

        Note:
            The session should be used within an async context manager:
            async with ctx.get_db_session() as session:
                # Use session here
        """
        get_session = self.context.get("get_session")
        if not get_session:
            raise RuntimeError("Database session factory not available in context")
        return get_session()

    def get_service(self, service_type: type) -> Any:
        """
        Get a service from the DI container.

        Args:
            service_type: The service type to retrieve

        Returns:
            The service instance

        Raises:
            RuntimeError: If container is not available
        """
        if not self.container:
            raise RuntimeError("DI container not available in context")
        return self.container.resolve(service_type)

    def require_authentication(self) -> Any:
        """
        Require authentication for the resolver.

        Returns:
            The authenticated user

        Raises:
            RuntimeError: If user is not authenticated
        """
        if not self.is_authenticated:
            raise RuntimeError("Authentication required")
        return self.user

    def require_permission(self, permission: str) -> Any:
        """
        Require a specific permission for the resolver.

        Args:
            permission: The permission to check

        Returns:
            The authenticated user

        Raises:
            RuntimeError: If user doesn't have the permission
        """
        user = self.require_authentication()

        # Check permission logic here
        # This is a placeholder - actual implementation would check user permissions
        if not hasattr(user, "has_permission") or not user.has_permission(permission):
            raise RuntimeError(f"Permission '{permission}' required")

        return user


def get_context(info: Info) -> GraphQLContext:
    """
    Get a GraphQL context helper from Strawberry info.

    Args:
        info: Strawberry Info object

    Returns:
        GraphQLContext: Context helper instance
    """
    return GraphQLContext(info)


# Decorators for common resolver patterns


def authenticated(func):
    """
    Decorator to require authentication for a resolver.

    Usage:
        @authenticated
        async def my_resolver(self, info: Info) -> str:
            ctx = get_context(info)
            user = ctx.user  # Guaranteed to be authenticated
            ...
    """

    async def wrapper(*args, **kwargs):
        # Find the info argument
        info = None
        for arg in args:
            if isinstance(arg, Info):
                info = arg
                break
        if not info:
            for arg in kwargs.values():
                if isinstance(arg, Info):
                    info = arg
                    break

        if not info:
            raise RuntimeError("No Info object found in resolver arguments")

        ctx = get_context(info)
        ctx.require_authentication()

        return await func(*args, **kwargs)

    return wrapper


def with_permission(permission: str):
    """
    Decorator to require a specific permission for a resolver.

    Usage:
        @with_permission("users:read")
        async def get_users(self, info: Info) -> list[User]:
            ...
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Find the info argument
            info = None
            for arg in args:
                if isinstance(arg, Info):
                    info = arg
                    break
            if not info:
                for arg in kwargs.values():
                    if isinstance(arg, Info):
                        info = arg
                        break

            if not info:
                raise RuntimeError("No Info object found in resolver arguments")

            ctx = get_context(info)
            ctx.require_permission(permission)

            return await func(*args, **kwargs)

        return wrapper

    return decorator


__all__ = ["GraphQLContext", "authenticated", "get_context", "with_permission"]
