"""SQLAlchemy model for notification schedules."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID

from app.core.infrastructure.database import Base
from app.modules.notification.domain.enums import NotificationChannel, ScheduleStatus


class ScheduleModel(Base):
    """Database model for notification schedules."""

    __tablename__ = "notification_schedules"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True)

    # Basic fields
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # Template reference
    template_id = Column(PostgresUUID(as_uuid=True), nullable=False, index=True)
    channel = Column(Enum(NotificationChannel), nullable=False)

    # Schedule configuration
    cron_expression = Column(String(100), nullable=True)  # For recurring schedules
    scheduled_at = Column(DateTime, nullable=True)  # For one-time schedules
    timezone = Column(String(50), nullable=True, default="UTC")

    # Recurrence settings
    is_recurring = Column(Boolean, nullable=False, default=False)
    max_occurrences = Column(Integer, nullable=True)
    occurrences_count = Column(Integer, nullable=False, default=0)

    # Date range
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=True)

    # Target configuration
    recipient_query = Column(JSON, nullable=True)  # Query to select recipients
    recipient_list = Column(JSON, nullable=True)  # Fixed list of recipient IDs

    # Template variables
    template_variables = Column(JSON, nullable=True)

    # Status
    status = Column(
        Enum(ScheduleStatus), nullable=False, default=ScheduleStatus.ACTIVE, index=True
    )

    # Execution tracking
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True, index=True)
    last_run_status = Column(String(50), nullable=True)
    last_run_error = Column(Text, nullable=True)

    # Statistics
    total_sent = Column(Integer, nullable=False, default=0)
    total_delivered = Column(Integer, nullable=False, default=0)
    total_failed = Column(Integer, nullable=False, default=0)

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
        Index("idx_schedules_status_next_run", "status", "next_run_at"),
        Index("idx_schedules_template", "template_id"),
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "template_id": str(self.template_id),
            "channel": self.channel.value if self.channel else None,
            "cron_expression": self.cron_expression,
            "scheduled_at": self.scheduled_at.isoformat()
            if self.scheduled_at
            else None,
            "timezone": self.timezone,
            "is_recurring": self.is_recurring,
            "max_occurrences": self.max_occurrences,
            "occurrences_count": self.occurrences_count,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "recipient_query": self.recipient_query,
            "recipient_list": self.recipient_list,
            "template_variables": self.template_variables,
            "status": self.status.value if self.status else None,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "last_run_status": self.last_run_status,
            "last_run_error": self.last_run_error,
            "total_sent": self.total_sent,
            "total_delivered": self.total_delivered,
            "total_failed": self.total_failed,
            "metadata": self.metadata,
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
