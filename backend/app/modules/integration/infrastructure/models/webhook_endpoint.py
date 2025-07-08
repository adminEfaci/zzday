"""Webhook endpoint database model.

This module provides the SQLAlchemy model for webhook endpoints.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.infrastructure.database import Base, UtcTimestampMixin


class WebhookEndpointModel(Base, UtcTimestampMixin):
    """SQLAlchemy model for webhook endpoints."""

    __tablename__ = "webhook_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "integration_id", "path", name="uq_webhook_endpoints_integration_path"
        ),
        Index("idx_webhook_endpoints_integration_id", "integration_id"),
        Index("idx_webhook_endpoints_secret_token", "secret_token"),
        Index("idx_webhook_endpoints_active", "is_active"),
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

    # Core attributes
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Webhook configuration
    allowed_methods: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    secret_token: Mapped[str] = mapped_column(String(255), nullable=False)

    # Signature configuration (stored as JSON)
    signature_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Event configuration
    event_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Headers configuration
    required_headers: Mapped[dict[str, str]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # State fields
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Rate limiting (stored as JSON)
    rate_limit_config: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )

    # Processing configuration
    retry_config: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    # Additional metadata
    metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    integration: Mapped["IntegrationModel"] = relationship(
        "IntegrationModel", back_populates="webhook_endpoints", lazy="select"
    )

    events: Mapped[list["WebhookEventModel"]] = relationship(
        "WebhookEventModel",
        back_populates="endpoint",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def to_entity_dict(self) -> dict[str, Any]:
        """Convert model to entity dictionary."""
        return {
            "entity_id": self.id,
            "integration_id": self.integration_id,
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "allowed_methods": self.allowed_methods,
            "secret_token": self.secret_token,
            "signature_config": self.signature_config,
            "event_types": self.event_types,
            "required_headers": self.required_headers,
            "is_active": self.is_active,
            "rate_limit_config": self.rate_limit_config,
            "retry_config": self.retry_config,
            "timeout_seconds": self.timeout_seconds,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
            # Include event count
            "_event_count": len(self.events) if self.events else 0,
        }

    @classmethod
    def from_entity_dict(cls, data: dict[str, Any]) -> "WebhookEndpointModel":
        """Create model from entity dictionary."""
        # Extract fields
        entity_id = data.pop("entity_id", data.get("id"))

        # Remove computed fields
        data.pop("_event_count", None)
        data.pop("full_url", None)
        data.pop("is_rate_limited", None)
        data.pop("supports_retries", None)
        data.pop("event_count", None)

        # Convert WebhookMethod enums to strings if needed
        if "allowed_methods" in data:
            methods = data["allowed_methods"]
            if methods and hasattr(methods[0], "value"):
                data["allowed_methods"] = [m.value for m in methods]

        return cls(id=entity_id, **data)

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<WebhookEndpointModel(id={self.id}, name={self.name}, path={self.path})>"
        )
