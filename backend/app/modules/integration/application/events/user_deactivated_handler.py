"""User deactivated event handler.

This module provides the event handler for UserDeactivatedEvent,
implementing automatic access revocation in external systems.
"""

from typing import Any
from uuid import UUID

from app.core.logging import get_logger

logger = get_logger(__name__)


class UserDeactivatedEventHandler:
    """Handler for UserDeactivatedEvent from Identity module."""

    def __init__(
        self,
        integration_repository: Any,
        external_api_client: Any,
        credential_repository: Any,
    ):
        """Initialize event handler.

        Args:
            integration_repository: Repository for integrations
            external_api_client: Client for external API calls
            credential_repository: Repository for credentials
        """
        self._integration_repository = integration_repository
        self._external_api_client = external_api_client
        self._credential_repository = credential_repository

    async def handle(self, event: Any) -> None:
        """Handle UserDeactivatedEvent.

        Args:
            event: UserDeactivatedEvent from Identity module
        """
        logger.info(
            "Handling user deactivated event",
            user_id=event.user_id,
            reason=event.reason,
            deactivated_by=event.deactivated_by,
            correlation_id=event.metadata.correlation_id if event.metadata else None,
        )

        try:
            # Find integrations that need access revocation
            access_integrations = await self._get_access_integrations()

            # Revoke access in each integration
            revocation_results = []
            for integration in access_integrations:
                result = await self._revoke_external_access(integration, event)
                revocation_results.append(result)

            # Deactivate user-owned integrations
            user_integrations = await self._get_user_owned_integrations(event.user_id)
            for integration in user_integrations:
                await self._deactivate_user_integration(integration, event)

            # Generate summary
            successful_revocations = sum(1 for r in revocation_results if r["success"])

            logger.info(
                "User deactivation processed",
                user_id=event.user_id,
                access_revocations=successful_revocations,
                total_integrations=len(access_integrations),
                deactivated_integrations=len(user_integrations),
            )

        except Exception as e:
            logger.exception(
                "Failed to process user deactivation",
                user_id=event.user_id,
                error=str(e),
            )
            # Don't raise - this is async processing

    async def _get_access_integrations(self) -> list[Any]:
        """Get integrations that support access management.

        Returns:
            list[Any]: Access management integrations
        """
        filters = {
            "is_active": True,
            "is_connected": True,
            "capabilities": ["access_management", "user_management"],
        }

        integrations = await self._integration_repository.get_by_filters(filters)

        # Filter for integrations that support access revocation
        access_integrations = []
        for integration in integrations:
            if self._supports_access_revocation(integration):
                access_integrations.append(integration)

        return access_integrations

    def _supports_access_revocation(self, integration: Any) -> bool:
        """Check if integration supports access revocation.

        Args:
            integration: Integration to check

        Returns:
            bool: True if supports access revocation
        """
        # Check integration configuration for access revocation capability
        config = integration.configuration
        return "access_management" in config and config["access_management"].get(
            "supports_revocation", False
        )

    async def _revoke_external_access(
        self, integration: Any, event: Any
    ) -> dict[str, Any]:
        """Revoke user access in external system.

        Args:
            integration: External integration
            event: User deactivated event

        Returns:
            dict[str, Any]: Revocation result
        """
        result = {
            "integration_id": integration.id,
            "system_name": integration.system_name,
            "success": False,
            "error": None,
            "actions_taken": [],
        }

        try:
            # Check if user exists in external system
            user_exists = await self._external_api_client.check_user_exists(
                integration=integration, user_id=str(event.user_id)
            )

            if not user_exists:
                logger.info(
                    "User not found in external system",
                    integration_id=integration.id,
                    user_id=event.user_id,
                )
                result["success"] = True
                result["actions_taken"].append("user_not_found")
                return result

            # Determine revocation strategy based on integration type
            revocation_strategy = self._get_revocation_strategy(integration)

            if revocation_strategy == "disable":
                # Disable user account
                await self._external_api_client.disable_user(
                    integration=integration,
                    user_id=str(event.user_id),
                    reason=event.reason,
                    metadata={
                        "correlation_id": str(event.metadata.correlation_id)
                        if event.metadata
                        else None,
                        "deactivated_by": str(event.deactivated_by)
                        if event.deactivated_by
                        else None,
                    },
                )
                result["actions_taken"].append("account_disabled")

            elif revocation_strategy == "revoke_tokens":
                # Revoke access tokens
                await self._external_api_client.revoke_user_tokens(
                    integration=integration, user_id=str(event.user_id)
                )
                result["actions_taken"].append("tokens_revoked")

            elif revocation_strategy == "remove_permissions":
                # Remove all permissions
                await self._external_api_client.remove_all_permissions(
                    integration=integration, user_id=str(event.user_id)
                )
                result["actions_taken"].append("permissions_removed")

            elif revocation_strategy == "delete":
                # Delete user account (use with caution)
                await self._external_api_client.delete_user(
                    integration=integration,
                    user_id=str(event.user_id),
                    reason=event.reason,
                )
                result["actions_taken"].append("account_deleted")

            result["success"] = True

            logger.info(
                "External access revoked successfully",
                integration_id=integration.id,
                user_id=event.user_id,
                strategy=revocation_strategy,
                actions=result["actions_taken"],
            )

        except Exception as e:
            logger.exception(
                "Failed to revoke external access",
                integration_id=integration.id,
                user_id=event.user_id,
                error=str(e),
            )
            result["error"] = str(e)

        return result

    def _get_revocation_strategy(self, integration: Any) -> str:
        """Get revocation strategy for integration.

        Args:
            integration: Integration

        Returns:
            str: Revocation strategy
        """
        config = integration.configuration.get("access_management", {})
        strategy = config.get("revocation_strategy", "disable")

        # Validate strategy
        valid_strategies = ["disable", "revoke_tokens", "remove_permissions", "delete"]
        if strategy not in valid_strategies:
            logger.warning(
                "Invalid revocation strategy, using default",
                integration_id=integration.id,
                strategy=strategy,
            )
            return "disable"

        return strategy

    async def _get_user_owned_integrations(self, user_id: UUID) -> list[Any]:
        """Get integrations owned by user.

        Args:
            user_id: User ID

        Returns:
            list[Any]: User-owned integrations
        """
        filters = {"owner_id": user_id, "is_active": True}

        return await self._integration_repository.get_by_filters(filters)

    async def _deactivate_user_integration(self, integration: Any, event: Any) -> None:
        """Deactivate user-owned integration.

        Args:
            integration: User integration
            event: User deactivated event
        """
        try:
            # Disconnect if connected
            if integration.is_connected:
                integration.disconnect(
                    user_id=event.deactivated_by,
                    reason=f"User deactivated: {event.reason}",
                )

            # Deactivate integration
            integration.deactivate()

            # Save changes
            await self._integration_repository.save(integration)

            logger.info(
                "User integration deactivated",
                integration_id=integration.id,
                user_id=event.user_id,
            )

        except Exception as e:
            logger.exception(
                "Failed to deactivate user integration",
                integration_id=integration.id,
                user_id=event.user_id,
                error=str(e),
            )
