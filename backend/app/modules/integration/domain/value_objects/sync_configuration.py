"""Sync configuration value object for integration synchronization settings.

This module provides the SyncConfiguration value object that encapsulates
all configuration settings for data synchronization operations.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.modules.integration.domain.enums import EntityType, SyncDirection


@dataclass(frozen=True)
class SyncConfiguration(ValueObject):
    """Value object representing synchronization configuration.

    This immutable object encapsulates all configuration settings
    needed for data synchronization between systems.
    """

    # Basic configuration
    direction: SyncDirection
    entity_type: EntityType
    sync_interval: timedelta

    # Filtering and selection
    filter_criteria: dict[str, Any] = field(default_factory=dict)
    selected_fields: list[str] = field(default_factory=list)
    excluded_fields: list[str] = field(default_factory=list)

    # Sync behavior
    batch_size: int = 100
    max_retries: int = 3
    retry_delay: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    # Conflict resolution
    conflict_resolution: str = (
        "newer_wins"  # newer_wins, source_wins, target_wins, manual
    )

    # Advanced options
    enable_delta_sync: bool = True
    track_deletions: bool = True
    preserve_timestamps: bool = True

    # Custom settings
    custom_settings: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Validate the sync configuration."""
        # Validate batch size
        if self.batch_size <= 0:
            raise ValidationError("Batch size must be positive")
        if self.batch_size > 10000:
            raise ValidationError("Batch size cannot exceed 10000")

        # Validate sync interval
        if self.sync_interval.total_seconds() < 60:
            raise ValidationError("Sync interval must be at least 1 minute")
        if self.sync_interval.total_seconds() > 86400 * 7:  # 7 days
            raise ValidationError("Sync interval cannot exceed 7 days")

        # Validate retries
        if self.max_retries < 0:
            raise ValidationError("Max retries cannot be negative")
        if self.max_retries > 10:
            raise ValidationError("Max retries cannot exceed 10")

        # Validate retry delay
        if self.retry_delay.total_seconds() < 1:
            raise ValidationError("Retry delay must be at least 1 second")
        if self.retry_delay.total_seconds() > 3600:  # 1 hour
            raise ValidationError("Retry delay cannot exceed 1 hour")

        # Validate conflict resolution
        valid_resolutions = {"newer_wins", "source_wins", "target_wins", "manual"}
        if self.conflict_resolution not in valid_resolutions:
            raise ValidationError(
                f"Invalid conflict resolution: {self.conflict_resolution}. "
                f"Must be one of: {', '.join(valid_resolutions)}"
            )

        # Validate field selections
        if self.selected_fields and self.excluded_fields:
            overlap = set(self.selected_fields) & set(self.excluded_fields)
            if overlap:
                raise ValidationError(
                    f"Fields cannot be both selected and excluded: {', '.join(overlap)}"
                )

    @property
    def is_bidirectional(self) -> bool:
        """Check if sync is bidirectional."""
        return self.direction == SyncDirection.BIDIRECTIONAL

    @property
    def supports_import(self) -> bool:
        """Check if configuration supports importing data."""
        return self.direction.allows_import

    @property
    def supports_export(self) -> bool:
        """Check if configuration supports exporting data."""
        return self.direction.allows_export

    @property
    def sync_interval_minutes(self) -> int:
        """Get sync interval in minutes."""
        return int(self.sync_interval.total_seconds() / 60)

    @property
    def has_field_filtering(self) -> bool:
        """Check if field filtering is enabled."""
        return bool(self.selected_fields or self.excluded_fields)

    @property
    def has_data_filtering(self) -> bool:
        """Check if data filtering is enabled."""
        return bool(self.filter_criteria)

    def get_effective_fields(self, available_fields: list[str]) -> list[str]:
        """Get the effective list of fields to sync.

        Args:
            available_fields: List of all available fields

        Returns:
            List of fields that should be synced
        """
        if self.selected_fields:
            # Use only selected fields that are available
            return [f for f in self.selected_fields if f in available_fields]
        if self.excluded_fields:
            # Use all available fields except excluded ones
            return [f for f in available_fields if f not in self.excluded_fields]
        # Use all available fields
        return available_fields

    def with_updated_interval(self, new_interval: timedelta) -> "SyncConfiguration":
        """Create a new configuration with updated sync interval.

        Args:
            new_interval: New sync interval

        Returns:
            New SyncConfiguration instance
        """
        return SyncConfiguration(
            direction=self.direction,
            entity_type=self.entity_type,
            sync_interval=new_interval,
            filter_criteria=self.filter_criteria,
            selected_fields=self.selected_fields,
            excluded_fields=self.excluded_fields,
            batch_size=self.batch_size,
            max_retries=self.max_retries,
            retry_delay=self.retry_delay,
            conflict_resolution=self.conflict_resolution,
            enable_delta_sync=self.enable_delta_sync,
            track_deletions=self.track_deletions,
            preserve_timestamps=self.preserve_timestamps,
            custom_settings=self.custom_settings,
        )

    def with_batch_size(self, batch_size: int) -> "SyncConfiguration":
        """Create a new configuration with updated batch size.

        Args:
            batch_size: New batch size

        Returns:
            New SyncConfiguration instance
        """
        return SyncConfiguration(
            direction=self.direction,
            entity_type=self.entity_type,
            sync_interval=self.sync_interval,
            filter_criteria=self.filter_criteria,
            selected_fields=self.selected_fields,
            excluded_fields=self.excluded_fields,
            batch_size=batch_size,
            max_retries=self.max_retries,
            retry_delay=self.retry_delay,
            conflict_resolution=self.conflict_resolution,
            enable_delta_sync=self.enable_delta_sync,
            track_deletions=self.track_deletions,
            preserve_timestamps=self.preserve_timestamps,
            custom_settings=self.custom_settings,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the configuration
        """
        return {
            "direction": self.direction.value,
            "entity_type": self.entity_type.value,
            "sync_interval_seconds": int(self.sync_interval.total_seconds()),
            "filter_criteria": self.filter_criteria,
            "selected_fields": self.selected_fields,
            "excluded_fields": self.excluded_fields,
            "batch_size": self.batch_size,
            "max_retries": self.max_retries,
            "retry_delay_seconds": int(self.retry_delay.total_seconds()),
            "conflict_resolution": self.conflict_resolution,
            "enable_delta_sync": self.enable_delta_sync,
            "track_deletions": self.track_deletions,
            "preserve_timestamps": self.preserve_timestamps,
            "custom_settings": self.custom_settings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SyncConfiguration":
        """Create from dictionary representation.

        Args:
            data: Dictionary containing configuration data

        Returns:
            SyncConfiguration instance
        """
        return cls(
            direction=SyncDirection(data["direction"]),
            entity_type=EntityType(data["entity_type"]),
            sync_interval=timedelta(seconds=data["sync_interval_seconds"]),
            filter_criteria=data.get("filter_criteria", {}),
            selected_fields=data.get("selected_fields", []),
            excluded_fields=data.get("excluded_fields", []),
            batch_size=data.get("batch_size", 100),
            max_retries=data.get("max_retries", 3),
            retry_delay=timedelta(seconds=data.get("retry_delay_seconds", 30)),
            conflict_resolution=data.get("conflict_resolution", "newer_wins"),
            enable_delta_sync=data.get("enable_delta_sync", True),
            track_deletions=data.get("track_deletions", True),
            preserve_timestamps=data.get("preserve_timestamps", True),
            custom_settings=data.get("custom_settings", {}),
        )

    @classmethod
    def create_default(
        cls, direction: SyncDirection, entity_type: EntityType
    ) -> "SyncConfiguration":
        """Create a default configuration.

        Args:
            direction: Sync direction
            entity_type: Entity type to sync

        Returns:
            Default SyncConfiguration instance
        """
        return cls(
            direction=direction,
            entity_type=entity_type,
            sync_interval=timedelta(hours=1),
            filter_criteria={},
            selected_fields=[],
            excluded_fields=[],
            batch_size=100,
            max_retries=3,
            retry_delay=timedelta(seconds=30),
            conflict_resolution="newer_wins",
            enable_delta_sync=True,
            track_deletions=True,
            preserve_timestamps=True,
            custom_settings={},
        )
