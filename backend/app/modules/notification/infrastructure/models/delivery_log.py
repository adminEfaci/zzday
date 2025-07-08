"""SQLAlchemy model for notification delivery logs."""

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
from app.modules.notification.domain.enums import DeliveryStatus, NotificationChannel


class DeliveryLogModel(Base):
    """Database model for detailed notification delivery logs."""

    __tablename__ = "notification_delivery_logs"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True)

    # Notification reference
    notification_id = Column(PostgresUUID(as_uuid=True), nullable=False, index=True)

    # Delivery details
    channel = Column(Enum(NotificationChannel), nullable=False, index=True)
    provider = Column(String(100), nullable=False)
    provider_message_id = Column(String(500), nullable=True, index=True)

    # Status
    status = Column(Enum(DeliveryStatus), nullable=False, index=True)
    status_details = Column(Text, nullable=True)

    # Request/Response
    request_data = Column(JSON, nullable=True)  # Sanitized request data
    response_data = Column(JSON, nullable=True)  # Provider response

    # Error tracking
    error_code = Column(String(100), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    is_retryable = Column(Boolean, nullable=False, default=False)

    # Performance metrics
    request_duration_ms = Column(Integer, nullable=True)
    queue_duration_ms = Column(Integer, nullable=True)

    # Webhook data (for async delivery confirmation)
    webhook_received_at = Column(DateTime, nullable=True)
    webhook_data = Column(JSON, nullable=True)

    # Cost tracking
    cost_amount = Column(Integer, nullable=True)  # In cents
    cost_currency = Column(String(3), nullable=True)

    # Metadata
    metadata = Column(JSON, nullable=True)

    # Timestamp
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Indexes for common queries
    __table_args__ = (
        Index(
            "idx_delivery_logs_notification_created", "notification_id", "created_at"
        ),
        Index("idx_delivery_logs_channel_status", "channel", "status"),
        Index("idx_delivery_logs_provider_error", "provider", "error_code"),
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            "id": str(self.id),
            "notification_id": str(self.notification_id),
            "channel": self.channel.value if self.channel else None,
            "provider": self.provider,
            "provider_message_id": self.provider_message_id,
            "status": self.status.value if self.status else None,
            "status_details": self.status_details,
            "request_data": self.request_data,
            "response_data": self.response_data,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "is_retryable": self.is_retryable,
            "request_duration_ms": self.request_duration_ms,
            "queue_duration_ms": self.queue_duration_ms,
            "webhook_received_at": self.webhook_received_at.isoformat()
            if self.webhook_received_at
            else None,
            "webhook_data": self.webhook_data,
            "cost_amount": self.cost_amount,
            "cost_currency": self.cost_currency,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
