"""Notification Template Repository Interface.

Domain contract for notification template data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.notification.domain.aggregates.notification_template import (
    NotificationTemplate,
)
from app.modules.notification.domain.enums import NotificationChannel, TemplateType


class INotificationTemplateRepository(
    ISpecificationRepository[NotificationTemplate, UUID], ABC
):
    """Repository interface for NotificationTemplate aggregate operations."""

    @abstractmethod
    async def find_by_name(self, name: str) -> NotificationTemplate | None:
        """Find template by name."""

    @abstractmethod
    async def find_by_type(
        self, template_type: TemplateType, limit: int | None = None, offset: int = 0
    ) -> list[NotificationTemplate]:
        """Find templates by type."""

    @abstractmethod
    async def find_by_channel(
        self, channel: NotificationChannel, limit: int | None = None, offset: int = 0
    ) -> list[NotificationTemplate]:
        """Find templates supporting a specific channel."""

    @abstractmethod
    async def find_active_templates(
        self, limit: int | None = None, offset: int = 0
    ) -> list[NotificationTemplate]:
        """Find all active templates."""

    @abstractmethod
    async def find_default_templates(
        self, template_type: TemplateType | None = None
    ) -> list[NotificationTemplate]:
        """Find default templates by type."""

    @abstractmethod
    async def find_by_created_by(
        self, created_by: UUID, limit: int | None = None, offset: int = 0
    ) -> list[NotificationTemplate]:
        """Find templates created by a specific user."""

    @abstractmethod
    async def find_by_tags(
        self,
        tags: list[str],
        match_all: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationTemplate]:
        """Find templates by tags."""

    @abstractmethod
    async def find_recently_used(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[NotificationTemplate]:
        """Find recently used templates."""

    @abstractmethod
    async def find_unused_templates(
        self, unused_for_days: int = 90, limit: int | None = None, offset: int = 0
    ) -> list[NotificationTemplate]:
        """Find templates that haven't been used recently."""

    @abstractmethod
    async def find_templates_with_variables(
        self,
        variable_names: list[str],
        match_all: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationTemplate]:
        """Find templates using specific variables."""

    @abstractmethod
    async def find_templates_by_version(
        self,
        min_version: int | None = None,
        max_version: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationTemplate]:
        """Find templates by version range."""

    @abstractmethod
    async def search_templates(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationTemplate]:
        """Search templates by text query."""

    @abstractmethod
    async def name_exists(
        self, name: str, exclude_template_id: UUID | None = None
    ) -> bool:
        """Check if template name exists."""

    @abstractmethod
    async def get_template_statistics(self, template_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific template."""

    @abstractmethod
    async def get_usage_statistics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get template usage statistics."""

    @abstractmethod
    async def count_templates_by_type(self) -> dict[TemplateType, int]:
        """Count templates grouped by type."""

    @abstractmethod
    async def count_templates_by_channel(self) -> dict[NotificationChannel, int]:
        """Count templates grouped by supported channels."""

    @abstractmethod
    async def count_templates_by_status(self) -> dict[str, int]:
        """Count templates grouped by active status."""

    @abstractmethod
    async def get_most_used_templates(
        self, since: datetime | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get most frequently used templates."""

    @abstractmethod
    async def get_template_usage_trend(
        self, template_id: UUID, resolution_days: int = 1, days_back: int = 30
    ) -> dict[datetime, int]:
        """Get usage trend for a specific template."""

    @abstractmethod
    async def get_channel_coverage(
        self,
    ) -> dict[TemplateType, dict[NotificationChannel, int]]:
        """Get channel coverage by template type."""

    @abstractmethod
    async def find_template_conflicts(
        self, template_type: TemplateType, channel: NotificationChannel
    ) -> list[NotificationTemplate]:
        """Find potentially conflicting templates."""

    @abstractmethod
    async def validate_template_variables(
        self, template_id: UUID, sample_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate template with sample data."""

    @abstractmethod
    async def get_template_dependencies(self, template_id: UUID) -> dict[str, Any]:
        """Get templates that depend on this template."""

    @abstractmethod
    async def clone_template(
        self, template_id: UUID, new_name: str, created_by: UUID
    ) -> NotificationTemplate:
        """Clone an existing template."""

    @abstractmethod
    async def bulk_activate_templates(
        self, template_ids: list[UUID], updated_by: UUID
    ) -> int:
        """Bulk activate templates."""

    @abstractmethod
    async def bulk_deactivate_templates(
        self, template_ids: list[UUID], updated_by: UUID, reason: str | None = None
    ) -> int:
        """Bulk deactivate templates."""

    @abstractmethod
    async def cleanup_old_versions(
        self, keep_versions: int = 10, template_id: UUID | None = None
    ) -> int:
        """Clean up old template versions."""

    @abstractmethod
    async def archive_unused_templates(
        self, unused_for_days: int = 180, created_by: UUID | None = None
    ) -> int:
        """Archive templates that haven't been used."""

    @abstractmethod
    async def export_template(
        self, template_id: UUID, include_usage_stats: bool = False
    ) -> dict[str, Any]:
        """Export template configuration."""

    @abstractmethod
    async def import_template(
        self,
        template_data: dict[str, Any],
        imported_by: UUID,
        overwrite_existing: bool = False,
    ) -> NotificationTemplate:
        """Import template from configuration."""

    @abstractmethod
    async def backup_templates(
        self, template_ids: list[UUID] | None = None, include_inactive: bool = False
    ) -> dict[str, Any]:
        """Create backup of templates."""

    @abstractmethod
    async def restore_templates(
        self,
        backup_data: dict[str, Any],
        restored_by: UUID,
        overwrite_existing: bool = False,
    ) -> list[NotificationTemplate]:
        """Restore templates from backup."""

    @abstractmethod
    async def get_template_health_report(self) -> dict[str, Any]:
        """Get health report for all templates."""

    @abstractmethod
    async def detect_template_anomalies(
        self, time_window_days: int = 7, threshold_factor: float = 2.0
    ) -> list[dict[str, Any]]:
        """Detect anomalous template usage patterns."""

    @abstractmethod
    async def optimize_template_storage(self) -> dict[str, Any]:
        """Optimize template storage and return statistics."""
