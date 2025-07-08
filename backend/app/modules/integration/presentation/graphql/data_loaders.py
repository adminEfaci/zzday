"""Data loaders for Integration GraphQL operations.

This module provides DataLoader implementations to efficiently batch
and cache database queries for Integration module GraphQL operations.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from aiodataloader import DataLoader

from app.modules.integration.application.dto import (
    IntegrationDetailDTO,
    IntegrationHealthDTO,
    MappingConfigDTO,
    SyncJobDTO,
    WebhookEventDTO,
)
from app.modules.integration.application.services.health_service import HealthService
from app.modules.integration.application.services.integration_service import (
    IntegrationService,
)
from app.modules.integration.application.services.mapping_service import MappingService
from app.modules.integration.application.services.sync_service import SyncService
from app.modules.integration.application.services.webhook_service import WebhookService


@dataclass
class IntegrationDataLoader:
    """Data loaders for Integration module."""

    integration_service: IntegrationService
    health_service: HealthService
    webhook_service: WebhookService
    mapping_service: MappingService
    sync_service: SyncService

    def __post_init__(self):
        """Initialize data loaders."""
        # Integration loaders
        self.integration_loader = DataLoader(self._load_integrations)
        self.integration_config_loader = DataLoader(self._load_integration_configs)
        self.user_integrations_loader = DataLoader(self._load_user_integrations)

        # Health loaders
        self.health_status_loader = DataLoader(self._load_health_statuses)
        self.health_history_loader = DataLoader(self._load_health_histories)

        # Webhook loaders
        self.webhook_events_loader = DataLoader(self._load_webhook_events)
        self.webhook_history_loader = DataLoader(self._load_webhook_histories)

        # Mapping loaders
        self.mapping_configs_loader = DataLoader(self._load_mapping_configs)
        self.field_mappings_loader = DataLoader(self._load_field_mappings)

        # Sync loaders
        self.sync_jobs_loader = DataLoader(self._load_sync_jobs)
        self.sync_history_loader = DataLoader(self._load_sync_histories)

        # Credential loaders
        self.integration_credentials_loader = DataLoader(
            self._load_integration_credentials
        )

    # Integration loaders
    async def _load_integrations(
        self, integration_ids: list[UUID]
    ) -> list[IntegrationDetailDTO | None]:
        """Load integrations by IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                integration = await self.integration_service.get_integration(
                    integration_id
                )
                results.append(integration)
            except Exception:
                results.append(None)
        return results

    async def _load_integration_configs(
        self, integration_ids: list[UUID]
    ) -> list[dict[str, Any]]:
        """Load integration configurations by IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                config = await self.integration_service.get_integration_config(
                    integration_id
                )
                results.append(config)
            except Exception:
                results.append({})
        return results

    async def _load_user_integrations(
        self, user_ids: list[UUID]
    ) -> list[list[IntegrationDetailDTO]]:
        """Load integrations by user IDs."""
        results = []
        for user_id in user_ids:
            try:
                integrations = await self.integration_service.list_integrations(
                    owner_id=user_id
                )
                results.append(integrations)
            except Exception:
                results.append([])
        return results

    # Health loaders
    async def _load_health_statuses(
        self, integration_ids: list[UUID]
    ) -> list[IntegrationHealthDTO | None]:
        """Load health statuses by integration IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                health = await self.health_service.get_health_status(integration_id)
                results.append(health)
            except Exception:
                results.append(None)
        return results

    async def _load_health_histories(
        self, integration_ids: list[UUID]
    ) -> list[list[dict[str, Any]]]:
        """Load health histories by integration IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                history = await self.health_service.get_health_history(integration_id)
                results.append(history)
            except Exception:
                results.append([])
        return results

    # Webhook loaders
    async def _load_webhook_events(
        self, integration_ids: list[UUID]
    ) -> list[list[WebhookEventDTO]]:
        """Load webhook events by integration IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                events = await self.webhook_service.get_webhook_events(integration_id)
                results.append(events)
            except Exception:
                results.append([])
        return results

    async def _load_webhook_histories(
        self, webhook_ids: list[UUID]
    ) -> list[list[dict[str, Any]]]:
        """Load webhook histories by webhook IDs."""
        results = []
        for webhook_id in webhook_ids:
            try:
                history = await self.webhook_service.get_webhook_history(webhook_id)
                results.append(history)
            except Exception:
                results.append([])
        return results

    # Mapping loaders
    async def _load_mapping_configs(
        self, integration_ids: list[UUID]
    ) -> list[list[MappingConfigDTO]]:
        """Load mapping configurations by integration IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                mappings = await self.mapping_service.get_mappings(integration_id)
                results.append(mappings)
            except Exception:
                results.append([])
        return results

    async def _load_field_mappings(
        self, mapping_ids: list[UUID]
    ) -> list[list[dict[str, Any]]]:
        """Load field mappings by mapping IDs."""
        results = []
        for mapping_id in mapping_ids:
            try:
                fields = await self.mapping_service.get_field_mappings(mapping_id)
                results.append(fields)
            except Exception:
                results.append([])
        return results

    # Sync loaders
    async def _load_sync_jobs(
        self, integration_ids: list[UUID]
    ) -> list[list[SyncJobDTO]]:
        """Load sync jobs by integration IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                jobs = await self.sync_service.get_sync_jobs(integration_id)
                results.append(jobs)
            except Exception:
                results.append([])
        return results

    async def _load_sync_histories(
        self, sync_job_ids: list[UUID]
    ) -> list[list[dict[str, Any]]]:
        """Load sync histories by sync job IDs."""
        results = []
        for sync_job_id in sync_job_ids:
            try:
                history = await self.sync_service.get_sync_history(sync_job_id)
                results.append(history)
            except Exception:
                results.append([])
        return results

    # Credential loaders
    async def _load_integration_credentials(
        self, integration_ids: list[UUID]
    ) -> list[list[dict[str, Any]]]:
        """Load credentials by integration IDs."""
        results = []
        for integration_id in integration_ids:
            try:
                credentials = (
                    await self.integration_service.get_integration_credentials(
                        integration_id
                    )
                )
                results.append(credentials)
            except Exception:
                results.append([])
        return results

    # Utility methods for data loading
    async def load_integration(
        self, integration_id: UUID
    ) -> IntegrationDetailDTO | None:
        """Load a single integration."""
        return await self.integration_loader.load(integration_id)

    async def load_integrations(
        self, integration_ids: list[UUID]
    ) -> list[IntegrationDetailDTO | None]:
        """Load multiple integrations."""
        return await self.integration_loader.load_many(integration_ids)

    async def load_health_status(
        self, integration_id: UUID
    ) -> IntegrationHealthDTO | None:
        """Load health status for an integration."""
        return await self.health_status_loader.load(integration_id)

    async def load_webhook_events(self, integration_id: UUID) -> list[WebhookEventDTO]:
        """Load webhook events for an integration."""
        return await self.webhook_events_loader.load(integration_id)

    async def load_mapping_configs(
        self, integration_id: UUID
    ) -> list[MappingConfigDTO]:
        """Load mapping configurations for an integration."""
        return await self.mapping_configs_loader.load(integration_id)

    async def load_sync_jobs(self, integration_id: UUID) -> list[SyncJobDTO]:
        """Load sync jobs for an integration."""
        return await self.sync_jobs_loader.load(integration_id)

    def clear_cache(self, integration_id: UUID | None = None):
        """Clear data loader cache."""
        if integration_id:
            # Clear specific integration data
            self.integration_loader.clear(integration_id)
            self.health_status_loader.clear(integration_id)
            self.webhook_events_loader.clear(integration_id)
            self.mapping_configs_loader.clear(integration_id)
            self.sync_jobs_loader.clear(integration_id)
        else:
            # Clear all caches
            self.integration_loader.clear_all()
            self.integration_config_loader.clear_all()
            self.user_integrations_loader.clear_all()
            self.health_status_loader.clear_all()
            self.health_history_loader.clear_all()
            self.webhook_events_loader.clear_all()
            self.webhook_history_loader.clear_all()
            self.mapping_configs_loader.clear_all()
            self.field_mappings_loader.clear_all()
            self.sync_jobs_loader.clear_all()
            self.sync_history_loader.clear_all()
            self.integration_credentials_loader.clear_all()

    async def prime_cache(self, integration_id: UUID):
        """Pre-load common data for an integration."""
        # Load integration and related data in parallel
        await asyncio.gather(
            self.load_integration(integration_id),
            self.load_health_status(integration_id),
            self.load_webhook_events(integration_id),
            self.load_mapping_configs(integration_id),
            self.load_sync_jobs(integration_id),
            return_exceptions=True,
        )
