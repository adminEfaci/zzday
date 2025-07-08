"""Sync job database model.

This module provides the SQLAlchemy model for synchronization jobs.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.infrastructure.database import Base, UtcTimestampMixin
from app.modules.integration.domain.enums import SyncDirection, SyncStatus


class SyncJobModel(Base, UtcTimestampMixin):
    """SQLAlchemy model for synchronization jobs."""

    __tablename__ = "sync_jobs"
    __table_args__ = (
        Index("idx_sync_jobs_integration_id", "integration_id"),
        Index("idx_sync_jobs_status", "status"),
        Index("idx_sync_jobs_direction", "direction"),
        Index("idx_sync_jobs_started_at", "started_at"),
        Index("idx_sync_jobs_completed_at", "completed_at"),
        Index("idx_sync_jobs_scheduled_at", "scheduled_at"),
    )

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, nullable=False
    )

    # Foreign keys
    integration_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="CASCADE"),
        nullable=False,
    )

    initiated_by: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), nullable=False
    )

    # Core attributes
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Sync configuration
    direction: Mapped[SyncDirection] = mapped_column(
        SQLEnum(SyncDirection, native_enum=False), nullable=False
    )

    # Mapping configuration
    mapping_ids: Mapped[list[UUID]] = mapped_column(JSON, nullable=False, default=list)

    # Sync parameters
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # Filter configuration
    filters: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Status
    status: Mapped[SyncStatus] = mapped_column(
        SQLEnum(SyncStatus, native_enum=False),
        nullable=False,
        default=SyncStatus.PENDING,
    )

    # Timing
    scheduled_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Progress tracking
    total_records: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processed_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Result summary
    result_summary: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # Performance metrics
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Additional metadata
    metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    integration: Mapped["IntegrationModel"] = relationship(
        "IntegrationModel", back_populates="sync_jobs", lazy="select"
    )

    def to_entity_dict(self) -> dict[str, Any]:
        """Convert model to entity dictionary."""
        return {
            "entity_id": self.id,
            "integration_id": self.integration_id,
            "initiated_by": self.initiated_by,
            "name": self.name,
            "description": self.description,
            "direction": self.direction,
            "mapping_ids": self.mapping_ids,
            "parameters": self.parameters,
            "filters": self.filters,
            "status": self.status,
            "scheduled_at": self.scheduled_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_records": self.total_records,
            "processed_records": self.processed_records,
            "failed_records": self.failed_records,
            "skipped_records": self.skipped_records,
            "error_message": self.error_message,
            "error_details": self.error_details,
            "result_summary": self.result_summary,
            "metrics": self.metrics,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }

    @classmethod
    def from_entity_dict(cls, data: dict[str, Any]) -> "SyncJobModel":
        """Create model from entity dictionary."""
        # Extract fields
        entity_id = data.pop("entity_id", data.get("id"))

        # Remove computed fields
        computed_fields = [
            "is_complete",
            "is_running",
            "is_failed",
            "can_retry",
            "progress_percentage",
            "success_rate",
            "duration_seconds",
            "sync_status",
        ]
        for field in computed_fields:
            data.pop(field, None)

        return cls(id=entity_id, **data)

    def __repr__(self) -> str:
        """String representation."""
        return f"<SyncJobModel(id={self.id}, name={self.name}, status={self.status.value})>"
