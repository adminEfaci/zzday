"""Webhook event database model.

This module provides the SQLAlchemy model for webhook events.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.infrastructure.database import Base, UtcTimestampMixin
from app.modules.integration.domain.enums import WebhookStatus


class WebhookEventModel(Base, UtcTimestampMixin):
    """SQLAlchemy model for webhook events."""

    __tablename__ = "webhook_events"
    __table_args__ = (
        Index("idx_webhook_events_endpoint_id", "endpoint_id"),
        Index("idx_webhook_events_status", "status"),
        Index("idx_webhook_events_event_type", "event_type"),
        Index("idx_webhook_events_received_at", "received_at"),
        Index("idx_webhook_events_processed_at", "processed_at"),
    )

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, nullable=False
    )

    # Foreign keys
    endpoint_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Event identification
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Request data
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    headers: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    raw_body: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Signature verification
    signature: Mapped[str | None] = mapped_column(String(500), nullable=True)
    signature_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # Processing status
    status: Mapped[WebhookStatus] = mapped_column(
        SQLEnum(WebhookStatus, native_enum=False),
        nullable=False,
        default=WebhookStatus.PENDING,
    )

    # Timestamps
    received_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    processed_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Processing details
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_retry_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Error tracking
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Response data (if applicable)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Additional metadata
    metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    endpoint: Mapped["WebhookEndpointModel"] = relationship(
        "WebhookEndpointModel", back_populates="events", lazy="select"
    )

    def to_entity_dict(self) -> dict[str, Any]:
        """Convert model to entity dictionary."""
        return {
            "entity_id": self.id,
            "endpoint_id": self.endpoint_id,
            "external_id": self.external_id,
            "event_type": self.event_type,
            "method": self.method,
            "headers": self.headers,
            "payload": self.payload,
            "raw_body": self.raw_body,
            "signature": self.signature,
            "signature_valid": self.signature_valid,
            "status": self.status,
            "received_at": self.received_at,
            "processed_at": self.processed_at,
            "attempts": self.attempts,
            "last_attempt_at": self.last_attempt_at,
            "next_retry_at": self.next_retry_at,
            "error_message": self.error_message,
            "error_details": self.error_details,
            "response_status": self.response_status,
            "response_body": self.response_body,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }

    @classmethod
    def from_entity_dict(cls, data: dict[str, Any]) -> "WebhookEventModel":
        """Create model from entity dictionary."""
        # Extract fields
        entity_id = data.pop("entity_id", data.get("id"))

        # Remove computed fields
        data.pop("is_processed", None)
        data.pop("is_failed", None)
        data.pop("can_retry", None)
        data.pop("processing_duration", None)

        return cls(id=entity_id, **data)

    def __repr__(self) -> str:
        """String representation."""
        return f"<WebhookEventModel(id={self.id}, type={self.event_type}, status={self.status.value})>"
