"""User registered event handler.

This module provides the event handler for UserRegisteredEvent,
implementing automatic CRM synchronization for new users.
"""

from typing import Any
from uuid import UUID

from app.core.logging import get_logger
from app.modules.integration.application.services import IntegrationService, SyncService
from app.modules.integration.domain.enums import SyncDirection

logger = get_logger(__name__)


class UserRegisteredEventHandler:
    """Handler for UserRegisteredEvent from Identity module."""

    def __init__(
        self,
        integration_service: IntegrationService,
        sync_service: SyncService,
        integration_repository: Any,
        mapping_repository: Any,
    ):
        """Initialize event handler.

        Args:
            integration_service: Integration application service
            sync_service: Sync application service
            integration_repository: Repository for integrations
            mapping_repository: Repository for mappings
        """
        self._integration_service = integration_service
        self._sync_service = sync_service
        self._integration_repository = integration_repository
        self._mapping_repository = mapping_repository

    async def handle(self, event: Any) -> None:
        """Handle UserRegisteredEvent.

        Args:
            event: UserRegisteredEvent from Identity module
        """
        logger.info(
            "Handling user registered event",
            user_id=event.user_id,
            email=event.email,
            correlation_id=event.metadata.correlation_id if event.metadata else None,
        )

        try:
            # Find active CRM integrations
            crm_integrations = await self._get_active_crm_integrations()

            for integration in crm_integrations:
                await self._sync_user_to_crm(integration, event)

            logger.info(
                "User registration synchronized to CRM systems",
                user_id=event.user_id,
                integration_count=len(crm_integrations),
            )

        except Exception as e:
            logger.exception(
                "Failed to sync user registration to CRM",
                user_id=event.user_id,
                error=str(e),
            )
            # Don't raise - this is async processing

    async def _get_active_crm_integrations(self) -> list[Any]:
        """Get active CRM integrations.

        Returns:
            list[Any]: Active CRM integrations
        """
        # Get integrations that support CRM sync
        filters = {
            "is_active": True,
            "is_connected": True,
            "capabilities": ["sync", "crm"],
        }

        integrations = await self._integration_repository.get_by_filters(filters)

        # Filter for CRM-type integrations
        crm_integrations = []
        for integration in integrations:
            if self._is_crm_integration(integration):
                crm_integrations.append(integration)

        return crm_integrations

    def _is_crm_integration(self, integration: Any) -> bool:
        """Check if integration is CRM-related.

        Args:
            integration: Integration to check

        Returns:
            bool: True if CRM integration
        """
        crm_systems = [
            "salesforce",
            "hubspot",
            "pipedrive",
            "zoho",
            "monday",
            "airtable",
            "notion",
        ]

        system_name_lower = integration.system_name.lower()
        return any(crm in system_name_lower for crm in crm_systems)

    async def _sync_user_to_crm(self, integration: Any, event: Any) -> None:
        """Sync user data to CRM integration.

        Args:
            integration: CRM integration
            event: User registered event
        """
        try:
            # Find user mapping for this integration
            user_mapping = await self._find_user_mapping(integration.id)
            if not user_mapping:
                logger.warning(
                    "No user mapping found for CRM integration",
                    integration_id=integration.id,
                    system_name=integration.system_name,
                )
                return

            # Create sync job for user export
            from app.modules.integration.domain.entities import SyncJob

            sync_job = SyncJob(
                integration_id=integration.id,
                mapping_id=user_mapping.id,
                direction=SyncDirection.EXPORT,
                batch_size=1,  # Single user
                filters={"user_id": str(event.user_id), "email": event.email},
                options={
                    "source": "user_registration",
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata
                    else None,
                },
                created_by=event.user_id,
            )

            # Start sync
            await self._sync_service.start_sync(sync_job)

            logger.info(
                "User sync job created for CRM",
                integration_id=integration.id,
                sync_job_id=sync_job.id,
                user_id=event.user_id,
            )

        except Exception as e:
            logger.exception(
                "Failed to create user sync job for CRM",
                integration_id=integration.id,
                user_id=event.user_id,
                error=str(e),
            )

    async def _find_user_mapping(self, integration_id: UUID) -> Any:
        """Find user mapping for integration.

        Args:
            integration_id: Integration ID

        Returns:
            Any: User mapping or None
        """
        filters = {
            "integration_id": integration_id,
            "is_active": True,
            "target_entity": "user",  # Or 'contact', 'lead' depending on CRM
        }

        mappings = await self._mapping_repository.get_by_filters(filters)

        # Return the first active user mapping
        return mappings[0] if mappings else None
