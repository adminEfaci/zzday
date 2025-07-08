"""User role changed event handler.

This module provides the event handler for UserRoleChangedEvent,
implementing automatic permission updates in external systems.
"""

from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class UserRoleChangedEventHandler:
    """Handler for UserRoleChangedEvent from Identity module."""

    def __init__(
        self,
        integration_repository: Any,
        external_api_client: Any,
        permission_mapper: Any,
    ):
        """Initialize event handler.

        Args:
            integration_repository: Repository for integrations
            external_api_client: Client for external API calls
            permission_mapper: Service for mapping internal roles to external permissions
        """
        self._integration_repository = integration_repository
        self._external_api_client = external_api_client
        self._permission_mapper = permission_mapper

    async def handle(self, event: Any) -> None:
        """Handle UserRoleChangedEvent.

        Args:
            event: UserRoleChangedEvent from Identity module
        """
        logger.info(
            "Handling user role changed event",
            user_id=event.user_id,
            old_roles=event.old_roles,
            new_roles=event.new_roles,
            correlation_id=event.metadata.correlation_id if event.metadata else None,
        )

        try:
            # Find integrations that need permission updates
            permission_integrations = await self._get_permission_integrations()

            for integration in permission_integrations:
                await self._update_external_permissions(integration, event)

            logger.info(
                "User role changes synchronized to external systems",
                user_id=event.user_id,
                integration_count=len(permission_integrations),
            )

        except Exception as e:
            logger.exception(
                "Failed to sync role changes to external systems",
                user_id=event.user_id,
                error=str(e),
            )
            # Don't raise - this is async processing

    async def _get_permission_integrations(self) -> list[Any]:
        """Get integrations that support permission management.

        Returns:
            list[Any]: Permission-capable integrations
        """
        filters = {
            "is_active": True,
            "is_connected": True,
            "capabilities": ["permissions", "user_management"],
        }

        integrations = await self._integration_repository.get_by_filters(filters)

        # Filter for integrations that support permission sync
        permission_integrations = []
        for integration in integrations:
            if self._supports_permission_sync(integration):
                permission_integrations.append(integration)

        return permission_integrations

    def _supports_permission_sync(self, integration: Any) -> bool:
        """Check if integration supports permission synchronization.

        Args:
            integration: Integration to check

        Returns:
            bool: True if supports permission sync
        """
        # Check integration configuration for permission sync capability
        config = integration.configuration
        return "permission_sync" in config and config["permission_sync"].get(
            "enabled", False
        )

    async def _update_external_permissions(self, integration: Any, event: Any) -> None:
        """Update user permissions in external system.

        Args:
            integration: External integration
            event: User role changed event
        """
        try:
            # Map internal roles to external permissions
            old_permissions = await self._permission_mapper.map_roles_to_permissions(
                integration=integration, roles=event.old_roles
            )

            new_permissions = await self._permission_mapper.map_roles_to_permissions(
                integration=integration, roles=event.new_roles
            )

            # Calculate permission changes
            permissions_to_add = set(new_permissions) - set(old_permissions)
            permissions_to_remove = set(old_permissions) - set(new_permissions)

            if permissions_to_add or permissions_to_remove:
                # Update permissions in external system
                await self._external_api_client.update_user_permissions(
                    integration=integration,
                    user_id=str(event.user_id),
                    permissions_to_add=list(permissions_to_add),
                    permissions_to_remove=list(permissions_to_remove),
                    metadata={
                        "correlation_id": str(event.metadata.correlation_id)
                        if event.metadata
                        else None,
                        "changed_by": str(event.changed_by),
                        "reason": event.reason,
                    },
                )

                logger.info(
                    "External permissions updated",
                    integration_id=integration.id,
                    user_id=event.user_id,
                    added_permissions=list(permissions_to_add),
                    removed_permissions=list(permissions_to_remove),
                )
            else:
                logger.debug(
                    "No permission changes needed for external system",
                    integration_id=integration.id,
                    user_id=event.user_id,
                )

        except Exception as e:
            logger.exception(
                "Failed to update external permissions",
                integration_id=integration.id,
                user_id=event.user_id,
                error=str(e),
            )
            # Continue processing other integrations
