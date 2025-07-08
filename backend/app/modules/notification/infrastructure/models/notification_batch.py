"""SQLAlchemy model for NotificationBatch aggregate."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, Enum, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID

from app.core.infrastructure.database import Base
from app.modules.notification.domain.enums import BatchStatus, NotificationChannel


class NotificationBatchModel(Base):
    """Database model for notification batches."""

    __tablename__ = "notification_batches"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True)

    # Basic fields
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    channel = Column(Enum(NotificationChannel), nullable=False, index=True)

    # Template reference
    template_id = Column(PostgresUUID(as_uuid=True), nullable=True, index=True)

    # Status tracking
    status = Column(
        Enum(BatchStatus), nullable=False, default=BatchStatus.CREATED, index=True
    )

    # Processing stats
    total_notifications = Column(Integer, nullable=False, default=0)
    sent_count = Column(Integer, nullable=False, default=0)
    delivered_count = Column(Integer, nullable=False, default=0)
    failed_count = Column(Integer, nullable=False, default=0)
    cancelled_count = Column(Integer, nullable=False, default=0)

    # Timing
    scheduled_for = Column(DateTime, nullable=True, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Configuration
    batch_config = Column(JSON, nullable=True)  # Rate limits, retry config, etc.

    # Error tracking
    error_summary = Column(JSON, nullable=True)

    # Metadata
    metadata = Column(JSON, nullable=True)

    # Audit fields
    created_by = Column(PostgresUUID(as_uuid=True), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Indexes for common queries
    __table_args__ = (
        Index("idx_batches_status_scheduled", "status", "scheduled_for"),
        Index("idx_batches_created_at", "created_at"),
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "channel": self.channel.value if self.channel else None,
            "template_id": str(self.template_id) if self.template_id else None,
            "status": self.status.value if self.status else None,
            "total_notifications": self.total_notifications,
            "sent_count": self.sent_count,
            "delivered_count": self.delivered_count,
            "failed_count": self.failed_count,
            "cancelled_count": self.cancelled_count,
            "scheduled_for": self.scheduled_for.isoformat()
            if self.scheduled_for
            else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "batch_config": self.batch_config,
            "error_summary": self.error_summary,
            "metadata": self.metadata,
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
