"""Health check DTOs for application layer.

This module provides data transfer objects for integration health monitoring,
ensuring clean interfaces for health status reporting.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.enums import ConnectionStatus


@dataclass(frozen=True)
class HealthCheckResultDTO:
    """DTO for individual health check result."""

    check_name: str
    is_healthy: bool
    response_time_ms: float
    error_message: str | None
    details: dict[str, Any]
    checked_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "check_name": self.check_name,
            "is_healthy": self.is_healthy,
            "response_time_ms": self.response_time_ms,
            "error_message": self.error_message,
            "details": self.details,
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass(frozen=True)
class IntegrationHealthDTO:
    """DTO for integration health information."""

    integration_id: UUID
    integration_name: str
    status: ConnectionStatus
    is_healthy: bool
    last_check_at: datetime | None
    next_check_at: datetime | None
    consecutive_failures: int
    uptime_percentage: float
    average_response_time_ms: float
    health_checks: list[HealthCheckResultDTO]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "integration_id": str(self.integration_id),
            "integration_name": self.integration_name,
            "status": self.status.value,
            "is_healthy": self.is_healthy,
            "last_check_at": self.last_check_at.isoformat()
            if self.last_check_at
            else None,
            "next_check_at": self.next_check_at.isoformat()
            if self.next_check_at
            else None,
            "consecutive_failures": self.consecutive_failures,
            "uptime_percentage": round(self.uptime_percentage, 2),
            "average_response_time_ms": round(self.average_response_time_ms, 2),
            "health_checks": [check.to_dict() for check in self.health_checks],
        }


@dataclass(frozen=True)
class SystemStatusDTO:
    """DTO for overall system status."""

    total_integrations: int
    active_integrations: int
    connected_integrations: int
    healthy_integrations: int
    unhealthy_integrations: int
    integrations_needing_attention: int
    active_sync_jobs: int
    pending_webhooks: int
    system_uptime_percentage: float
    last_incident_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_integrations": self.total_integrations,
            "active_integrations": self.active_integrations,
            "connected_integrations": self.connected_integrations,
            "healthy_integrations": self.healthy_integrations,
            "unhealthy_integrations": self.unhealthy_integrations,
            "integrations_needing_attention": self.integrations_needing_attention,
            "active_sync_jobs": self.active_sync_jobs,
            "pending_webhooks": self.pending_webhooks,
            "system_uptime_percentage": round(self.system_uptime_percentage, 2),
            "last_incident_at": self.last_incident_at.isoformat()
            if self.last_incident_at
            else None,
        }
