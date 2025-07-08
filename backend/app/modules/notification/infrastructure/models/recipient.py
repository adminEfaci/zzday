"""SQLAlchemy model for notification recipients."""

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
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID

from app.core.infrastructure.database import Base
from app.modules.notification.domain.enums import NotificationChannel, RecipientStatus


class RecipientModel(Base):
    """Database model for notification recipients."""

    __tablename__ = "notification_recipients"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True)

    # User reference
    user_id = Column(PostgresUUID(as_uuid=True), nullable=False, index=True)

    # Channel and address
    channel = Column(Enum(NotificationChannel), nullable=False)
    address = Column(String(500), nullable=False)
    display_name = Column(String(200), nullable=True)

    # Status
    status = Column(
        Enum(RecipientStatus),
        nullable=False,
        default=RecipientStatus.ACTIVE,
        index=True,
    )

    # Verification
    is_verified = Column(Boolean, nullable=False, default=False)
    verified_at = Column(DateTime, nullable=True)
    verification_token = Column(String(200), nullable=True)
    verification_expires_at = Column(DateTime, nullable=True)

    # Preferences
    preferences = Column(JSON, nullable=True)  # Channel-specific preferences
    timezone = Column(String(50), nullable=True)
    language = Column(String(10), nullable=True)

    # Bounce/complaint tracking
    bounce_count = Column(Integer, nullable=False, default=0)
    complaint_count = Column(Integer, nullable=False, default=0)
    last_bounce_at = Column(DateTime, nullable=True)
    last_complaint_at = Column(DateTime, nullable=True)

    # Usage tracking
    last_notification_at = Column(DateTime, nullable=True)
    notification_count = Column(Integer, nullable=False, default=0)

    # Metadata
    metadata = Column(JSON, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Unique constraint on user_id + channel + address
    __table_args__ = (
        UniqueConstraint(
            "user_id", "channel", "address", name="uq_user_channel_address"
        ),
        Index("idx_recipients_user_status", "user_id", "status"),
        Index("idx_recipients_channel_status", "channel", "status"),
        Index("idx_recipients_address", "address"),
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "channel": self.channel.value if self.channel else None,
            "address": self.address,
            "display_name": self.display_name,
            "status": self.status.value if self.status else None,
            "is_verified": self.is_verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "preferences": self.preferences,
            "timezone": self.timezone,
            "language": self.language,
            "bounce_count": self.bounce_count,
            "complaint_count": self.complaint_count,
            "last_bounce_at": self.last_bounce_at.isoformat()
            if self.last_bounce_at
            else None,
            "last_complaint_at": self.last_complaint_at.isoformat()
            if self.last_complaint_at
            else None,
            "last_notification_at": self.last_notification_at.isoformat()
            if self.last_notification_at
            else None,
            "notification_count": self.notification_count,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
