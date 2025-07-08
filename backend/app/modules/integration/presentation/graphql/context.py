"""GraphQL context for Integration module.

This module provides context management for Integration GraphQL operations,
including authentication, rate limiting, and service access.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.core.graphql.context import BaseContext
from app.modules.integration.application.services.health_service import HealthService
from app.modules.integration.application.services.integration_service import (
    IntegrationService,
)
from app.modules.integration.application.services.mapping_service import MappingService
from app.modules.integration.application.services.sync_service import SyncService
from app.modules.integration.application.services.webhook_service import WebhookService


@dataclass
class IntegrationContext(BaseContext):
    """Context for Integration GraphQL operations."""

    integration_service: IntegrationService
    health_service: HealthService
    webhook_service: WebhookService
    mapping_service: MappingService
    sync_service: SyncService

    # Rate limiting
    rate_limit_cache: dict[str, dict[str, Any]]

    # Current integration context
    current_integration_id: UUID | None = None
    current_integration: Any | None = None

    def __post_init__(self):
        """Initialize context after creation."""
        super().__post_init__()
        if not hasattr(self, "rate_limit_cache"):
            self.rate_limit_cache = {}

    def set_current_integration(self, integration_id: UUID) -> None:
        """Set the current integration context."""
        self.current_integration_id = integration_id
        # Load integration lazily when first accessed
        self.current_integration = None

    async def get_current_integration(self) -> Any | None:
        """Get the current integration, loading if necessary."""
        if self.current_integration_id and not self.current_integration:
            self.current_integration = await self.integration_service.get_integration(
                self.current_integration_id
            )
        return self.current_integration

    def check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check if rate limit is exceeded for given key."""
        import time

        now = time.time()
        if key not in self.rate_limit_cache:
            self.rate_limit_cache[key] = {"count": 0, "window_start": now}

        cache_entry = self.rate_limit_cache[key]

        # Reset window if expired
        if now - cache_entry["window_start"] > window:
            cache_entry["count"] = 0
            cache_entry["window_start"] = now

        if cache_entry["count"] >= limit:
            return False

        cache_entry["count"] += 1
        return True

    def get_rate_limit_info(self, key: str) -> dict[str, Any]:
        """Get rate limit information for a key."""
        if key not in self.rate_limit_cache:
            return {"remaining": 0, "reset_time": 0}

        cache_entry = self.rate_limit_cache[key]
        reset_time = cache_entry["window_start"] + 3600  # 1 hour window

        return {
            "remaining": max(
                0, 100 - cache_entry["count"]
            ),  # Assuming 100 requests per hour
            "reset_time": reset_time,
        }

    async def can_access_integration(self, integration_id: UUID) -> bool:
        """Check if current user can access the integration."""
        if not self.current_user:
            return False

        try:
            integration = await self.integration_service.get_integration(integration_id)
            return integration.owner_id == self.current_user.id
        except Exception:
            return False

    async def get_user_integrations(self) -> list:
        """Get all integrations for the current user."""
        if not self.current_user:
            return []

        return await self.integration_service.list_integrations(
            owner_id=self.current_user.id
        )

    def has_permission(self, permission: str) -> bool:
        """Check if current user has a specific permission."""
        if not self.current_user:
            return False

        # Check user permissions
        user_permissions = getattr(self.current_user, "permissions", [])
        return permission in user_permissions

    def is_admin(self) -> bool:
        """Check if current user is an admin."""
        return self.has_permission("admin") or self.has_permission("integration:admin")

    def can_manage_integrations(self) -> bool:
        """Check if current user can manage integrations."""
        return self.has_permission("integration:manage") or self.is_admin()

    def can_view_health(self) -> bool:
        """Check if current user can view health information."""
        return self.has_permission("integration:health:view") or self.is_admin()

    def can_manage_webhooks(self) -> bool:
        """Check if current user can manage webhooks."""
        return self.has_permission("integration:webhook:manage") or self.is_admin()

    def can_sync_data(self) -> bool:
        """Check if current user can perform data synchronization."""
        return self.has_permission("integration:sync") or self.is_admin()
