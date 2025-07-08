"""Data synchronization domain events.

This module provides domain events for data synchronization operations,
including start, completion, and failure tracking.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ValidationError
from app.core.events.types import DomainEvent, EventMetadata
from app.modules.integration.domain.enums import SyncDirection


class SyncStarted(DomainEvent):
    """Event raised when data synchronization starts."""

    def __init__(
        self,
        sync_id: UUID,
        integration_id: UUID,
        integration_name: str,
        direction: SyncDirection,
        started_by: UUID | None = None,
        is_scheduled: bool = False,
        total_records: int | None = None,
        sync_config: dict[str, Any] | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize sync started event.

        Args:
            sync_id: ID of the sync job
            integration_id: ID of the integration
            integration_name: Name of the integration
            direction: Sync direction
            started_by: User who started sync (if manual)
            is_scheduled: Whether sync was scheduled
            total_records: Expected total records
            sync_config: Sync configuration
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.sync_id = sync_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.direction = direction
        self.started_by = started_by
        self.is_scheduled = is_scheduled
        self.total_records = total_records
        self.sync_config = sync_config or {}

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = sync_id
            self.metadata.aggregate_type = "SyncJob"
            if started_by:
                self.metadata.user_id = started_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.sync_id:
            raise ValidationError("sync_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not isinstance(self.direction, SyncDirection):
            raise ValidationError("direction must be a SyncDirection enum")

        if not self.is_scheduled and not self.started_by:
            raise ValidationError("started_by is required for manual sync")

        if self.total_records is not None and self.total_records < 0:
            raise ValidationError("total_records cannot be negative")

        if not isinstance(self.sync_config, dict):
            raise ValidationError("sync_config must be a dictionary")


class SyncCompleted(DomainEvent):
    """Event raised when data synchronization completes successfully."""

    def __init__(
        self,
        sync_id: UUID,
        integration_id: UUID,
        integration_name: str,
        direction: SyncDirection,
        records_processed: int,
        records_failed: int,
        records_skipped: int,
        duration_seconds: float,
        started_at: datetime,
        completed_at: datetime,
        sync_summary: dict[str, Any] | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize sync completed event.

        Args:
            sync_id: ID of the sync job
            integration_id: ID of the integration
            integration_name: Name of the integration
            direction: Sync direction
            records_processed: Number of successfully processed records
            records_failed: Number of failed records
            records_skipped: Number of skipped records
            duration_seconds: Total duration in seconds
            started_at: When sync started
            completed_at: When sync completed
            sync_summary: Summary of sync operations
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.sync_id = sync_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.direction = direction
        self.records_processed = records_processed
        self.records_failed = records_failed
        self.records_skipped = records_skipped
        self.duration_seconds = duration_seconds
        self.started_at = started_at
        self.completed_at = completed_at
        self.sync_summary = sync_summary or {}

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = sync_id
            self.metadata.aggregate_type = "SyncJob"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.sync_id:
            raise ValidationError("sync_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not isinstance(self.direction, SyncDirection):
            raise ValidationError("direction must be a SyncDirection enum")

        if self.records_processed < 0:
            raise ValidationError("records_processed cannot be negative")

        if self.records_failed < 0:
            raise ValidationError("records_failed cannot be negative")

        if self.records_skipped < 0:
            raise ValidationError("records_skipped cannot be negative")

        if self.duration_seconds < 0:
            raise ValidationError("duration_seconds cannot be negative")

        if not isinstance(self.started_at, datetime):
            raise ValidationError("started_at must be a datetime")

        if not isinstance(self.completed_at, datetime):
            raise ValidationError("completed_at must be a datetime")

        if self.completed_at < self.started_at:
            raise ValidationError("completed_at cannot be before started_at")

        if not isinstance(self.sync_summary, dict):
            raise ValidationError("sync_summary must be a dictionary")


class SyncFailed(DomainEvent):
    """Event raised when data synchronization fails."""

    def __init__(
        self,
        sync_id: UUID,
        integration_id: UUID,
        integration_name: str,
        direction: SyncDirection,
        error_type: str,
        error_message: str,
        records_processed: int,
        records_failed: int,
        can_resume: bool,
        checkpoint: dict[str, Any] | None = None,
        failed_at: datetime | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize sync failed event.

        Args:
            sync_id: ID of the sync job
            integration_id: ID of the integration
            integration_name: Name of the integration
            direction: Sync direction
            error_type: Type of error
            error_message: Error message
            records_processed: Records processed before failure
            records_failed: Records that failed
            can_resume: Whether sync can be resumed
            checkpoint: Checkpoint data for resuming
            failed_at: When sync failed
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.sync_id = sync_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.direction = direction
        self.error_type = error_type
        self.error_message = error_message
        self.records_processed = records_processed
        self.records_failed = records_failed
        self.can_resume = can_resume
        self.checkpoint = checkpoint
        self.failed_at = failed_at or datetime.utcnow()

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = sync_id
            self.metadata.aggregate_type = "SyncJob"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.sync_id:
            raise ValidationError("sync_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not isinstance(self.direction, SyncDirection):
            raise ValidationError("direction must be a SyncDirection enum")

        if not self.error_type:
            raise ValidationError("error_type is required")

        if not self.error_message:
            raise ValidationError("error_message is required")

        if self.records_processed < 0:
            raise ValidationError("records_processed cannot be negative")

        if self.records_failed < 0:
            raise ValidationError("records_failed cannot be negative")

        if not isinstance(self.failed_at, datetime):
            raise ValidationError("failed_at must be a datetime")


class SyncProgress(DomainEvent):
    """Event raised periodically during sync to report progress."""

    def __init__(
        self,
        sync_id: UUID,
        integration_id: UUID,
        records_processed: int,
        records_failed: int,
        records_skipped: int,
        total_records: int | None = None,
        current_checkpoint: dict[str, Any] | None = None,
        estimated_completion: datetime | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize sync progress event.

        Args:
            sync_id: ID of the sync job
            integration_id: ID of the integration
            records_processed: Current processed count
            records_failed: Current failed count
            records_skipped: Current skipped count
            total_records: Total expected records
            current_checkpoint: Current checkpoint
            estimated_completion: Estimated completion time
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.sync_id = sync_id
        self.integration_id = integration_id
        self.records_processed = records_processed
        self.records_failed = records_failed
        self.records_skipped = records_skipped
        self.total_records = total_records
        self.current_checkpoint = current_checkpoint
        self.estimated_completion = estimated_completion

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = sync_id
            self.metadata.aggregate_type = "SyncJob"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.sync_id:
            raise ValidationError("sync_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if self.records_processed < 0:
            raise ValidationError("records_processed cannot be negative")

        if self.records_failed < 0:
            raise ValidationError("records_failed cannot be negative")

        if self.records_skipped < 0:
            raise ValidationError("records_skipped cannot be negative")

        if self.total_records is not None and self.total_records < 0:
            raise ValidationError("total_records cannot be negative")

        if self.estimated_completion and not isinstance(
            self.estimated_completion, datetime
        ):
            raise ValidationError("estimated_completion must be a datetime")


class SyncConflictDetected(DomainEvent):
    """Event raised when a sync conflict is detected."""

    def __init__(
        self,
        sync_id: UUID,
        integration_id: UUID,
        resource_type: str,
        resource_id: str,
        conflict_type: str,
        resolution_strategy: str,
        local_data: dict[str, Any],
        remote_data: dict[str, Any],
        metadata: EventMetadata | None = None,
    ):
        """Initialize sync conflict detected event.

        Args:
            sync_id: ID of the sync job
            integration_id: ID of the integration
            resource_type: Type of conflicting resource
            resource_id: ID of conflicting resource
            conflict_type: Type of conflict
            resolution_strategy: Strategy used to resolve
            local_data: Local data snapshot
            remote_data: Remote data snapshot
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.sync_id = sync_id
        self.integration_id = integration_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.conflict_type = conflict_type
        self.resolution_strategy = resolution_strategy
        self.local_data = local_data
        self.remote_data = remote_data

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = sync_id
            self.metadata.aggregate_type = "SyncJob"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.sync_id:
            raise ValidationError("sync_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.resource_type:
            raise ValidationError("resource_type is required")

        if not self.resource_id:
            raise ValidationError("resource_id is required")

        if not self.conflict_type:
            raise ValidationError("conflict_type is required")

        if not self.resolution_strategy:
            raise ValidationError("resolution_strategy is required")

        if not isinstance(self.local_data, dict):
            raise ValidationError("local_data must be a dictionary")

        if not isinstance(self.remote_data, dict):
            raise ValidationError("remote_data must be a dictionary")
