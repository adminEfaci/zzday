"""Integration DTOs for application layer.

This module provides data transfer objects for integration data,
ensuring clean interfaces without exposing domain internals.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType


@dataclass(frozen=True)
class IntegrationConfigDTO:
    """DTO for integration configuration data."""

    integration_id: UUID
    name: str
    integration_type: IntegrationType
    system_name: str
    api_base_url: str
    api_version: str | None
    timeout_seconds: int
    max_retries: int
    rate_limit_requests: int | None
    rate_limit_period: int | None
    capabilities: list[str]
    configuration: dict[str, Any]
    is_active: bool

    @classmethod
    def from_domain(cls, integration: Any) -> "IntegrationConfigDTO":
        """Create DTO from domain model."""
        return cls(
            integration_id=integration.id,
            name=integration.name,
            integration_type=integration.integration_type,
            system_name=integration.system_name,
            api_base_url=integration.api_endpoint.base_url,
            api_version=integration.api_endpoint.version,
            timeout_seconds=integration.api_endpoint.timeout_seconds,
            max_retries=integration.api_endpoint.max_retries,
            rate_limit_requests=integration.rate_limit.requests_per_period
            if integration.rate_limit
            else None,
            rate_limit_period=integration.rate_limit.period_seconds
            if integration.rate_limit
            else None,
            capabilities=integration.capabilities,
            configuration=integration._sanitize_configuration(),
            is_active=integration.is_active,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "integration_id": str(self.integration_id),
            "name": self.name,
            "integration_type": self.integration_type.value,
            "system_name": self.system_name,
            "api_base_url": self.api_base_url,
            "api_version": self.api_version,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_period": self.rate_limit_period,
            "capabilities": self.capabilities,
            "configuration": self.configuration,
            "is_active": self.is_active,
        }


@dataclass(frozen=True)
class IntegrationDetailDTO:
    """DTO for detailed integration information."""

    integration_id: UUID
    name: str
    description: str | None
    integration_type: IntegrationType
    system_name: str
    api_base_url: str
    api_version: str | None
    owner_id: UUID
    status: ConnectionStatus
    is_active: bool
    is_connected: bool
    is_healthy: bool
    needs_attention: bool
    can_sync: bool
    can_receive_webhooks: bool
    capabilities: list[str]
    configuration: dict[str, Any]
    last_health_check: datetime | None
    health_check_failures: int
    credential_count: int
    sync_job_count: int
    mapping_count: int
    webhook_endpoint_count: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_domain(cls, integration: Any) -> "IntegrationDetailDTO":
        """Create DTO from domain model."""
        return cls(
            integration_id=integration.id,
            name=integration.name,
            description=integration.description,
            integration_type=integration.integration_type,
            system_name=integration.system_name,
            api_base_url=integration.api_endpoint.base_url,
            api_version=integration.api_endpoint.version,
            owner_id=integration.owner_id,
            status=integration.status,
            is_active=integration.is_active,
            is_connected=integration.is_connected,
            is_healthy=integration.is_healthy,
            needs_attention=integration.needs_attention,
            can_sync=integration.can_sync,
            can_receive_webhooks=integration.can_receive_webhooks,
            capabilities=integration.capabilities,
            configuration=integration._sanitize_configuration(),
            last_health_check=integration.last_health_check,
            health_check_failures=integration.health_check_failures,
            credential_count=len(integration._credential_ids),
            sync_job_count=len(integration._sync_job_ids),
            mapping_count=len(integration._mapping_ids),
            webhook_endpoint_count=len(integration._webhook_endpoint_ids),
            created_at=integration.created_at,
            updated_at=integration.updated_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "integration_id": str(self.integration_id),
            "name": self.name,
            "description": self.description,
            "integration_type": self.integration_type.value,
            "system_name": self.system_name,
            "api_base_url": self.api_base_url,
            "api_version": self.api_version,
            "owner_id": str(self.owner_id),
            "status": self.status.value,
            "is_active": self.is_active,
            "is_connected": self.is_connected,
            "is_healthy": self.is_healthy,
            "needs_attention": self.needs_attention,
            "can_sync": self.can_sync,
            "can_receive_webhooks": self.can_receive_webhooks,
            "capabilities": self.capabilities,
            "configuration": self.configuration,
            "last_health_check": self.last_health_check.isoformat()
            if self.last_health_check
            else None,
            "health_check_failures": self.health_check_failures,
            "credential_count": self.credential_count,
            "sync_job_count": self.sync_job_count,
            "mapping_count": self.mapping_count,
            "webhook_endpoint_count": self.webhook_endpoint_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True)
class IntegrationListItemDTO:
    """DTO for integration list items."""

    integration_id: UUID
    name: str
    integration_type: IntegrationType
    system_name: str
    status: ConnectionStatus
    is_active: bool
    is_healthy: bool
    needs_attention: bool
    created_at: datetime

    @classmethod
    def from_domain(cls, integration: Any) -> "IntegrationListItemDTO":
        """Create DTO from domain model."""
        return cls(
            integration_id=integration.id,
            name=integration.name,
            integration_type=integration.integration_type,
            system_name=integration.system_name,
            status=integration.status,
            is_active=integration.is_active,
            is_healthy=integration.is_healthy,
            needs_attention=integration.needs_attention,
            created_at=integration.created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "integration_id": str(self.integration_id),
            "name": self.name,
            "integration_type": self.integration_type.value,
            "system_name": self.system_name,
            "status": self.status.value,
            "is_active": self.is_active,
            "is_healthy": self.is_healthy,
            "needs_attention": self.needs_attention,
            "created_at": self.created_at.isoformat(),
        }
