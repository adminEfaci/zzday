"""SQLAlchemy model for Notification entity."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, Enum, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID

from app.core.infrastructure.database import Base
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
)


class NotificationModel(Base):
    """Database model for notifications."""

    __tablename__ = "notifications"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True)

    # Core fields
    recipient_id = Column(PostgresUUID(as_uuid=True), nullable=False, index=True)
    channel = Column(Enum(NotificationChannel), nullable=False, index=True)
    priority = Column(
        Enum(NotificationPriority), nullable=False, default=NotificationPriority.NORMAL
    )

    # Content fields
    subject = Column(String(200), nullable=True)
    body = Column(Text, nullable=False)
    html_body = Column(Text, nullable=True)
    variables = Column(JSON, nullable=True)
    attachments = Column(JSON, nullable=True)

    # Recipient address
    recipient_address = Column(String(500), nullable=False)
    recipient_display_name = Column(String(200), nullable=True)

    # Template reference
    template_id = Column(PostgresUUID(as_uuid=True), nullable=True, index=True)

    # Status tracking
    current_status = Column(
        Enum(DeliveryStatus), nullable=False, default=DeliveryStatus.PENDING, index=True
    )
    status_history = Column(JSON, nullable=False, default=list)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    scheduled_for = Column(DateTime, nullable=True, index=True)
    sent_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    failed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)

    # Provider tracking
    provider = Column(String(100), nullable=True)
    provider_message_id = Column(String(500), nullable=True, index=True)
    provider_response = Column(JSON, nullable=True)

    # Retry tracking
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)
    next_retry_at = Column(DateTime, nullable=True, index=True)

    # Deduplication
    idempotency_key = Column(String(200), nullable=True, unique=True, index=True)

    # Metadata
    metadata = Column(JSON, nullable=True)

    # Indexes for common queries
    __table_args__ = (
        Index("idx_notifications_recipient_status", "recipient_id", "current_status"),
        Index("idx_notifications_channel_status", "channel", "current_status"),
        Index("idx_notifications_created_at", "created_at"),
        Index("idx_notifications_scheduled", "scheduled_for", "current_status"),
        Index("idx_notifications_retry", "next_retry_at", "current_status"),
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            "id": str(self.id),
            "recipient_id": str(self.recipient_id),
            "channel": self.channel.value if self.channel else None,
            "priority": self.priority.value if self.priority else None,
            "subject": self.subject,
            "body": self.body,
            "html_body": self.html_body,
            "variables": self.variables,
            "attachments": self.attachments,
            "recipient_address": self.recipient_address,
            "recipient_display_name": self.recipient_display_name,
            "template_id": str(self.template_id) if self.template_id else None,
            "current_status": self.current_status.value
            if self.current_status
            else None,
            "status_history": self.status_history,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "scheduled_for": self.scheduled_for.isoformat()
            if self.scheduled_for
            else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "delivered_at": self.delivered_at.isoformat()
            if self.delivered_at
            else None,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "failed_at": self.failed_at.isoformat() if self.failed_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "provider": self.provider,
            "provider_message_id": self.provider_message_id,
            "provider_response": self.provider_response,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "next_retry_at": self.next_retry_at.isoformat()
            if self.next_retry_at
            else None,
            "idempotency_key": self.idempotency_key,
            "metadata": self.metadata,
        }
