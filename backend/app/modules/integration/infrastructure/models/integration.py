"""Integration database model.

This module provides the SQLAlchemy model for Integration aggregates.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.infrastructure.database import Base, UtcTimestampMixin
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType


class IntegrationModel(Base, UtcTimestampMixin):
    """SQLAlchemy model for Integration aggregate."""

    __tablename__ = "integrations"
    __table_args__ = (
        UniqueConstraint("name", "owner_id", name="uq_integrations_name_owner"),
        Index("idx_integrations_owner_id", "owner_id"),
        Index("idx_integrations_system_name", "system_name"),
        Index("idx_integrations_status", "status"),
        Index("idx_integrations_type", "integration_type"),
        Index("idx_integrations_active", "is_active"),
    )

    # Primary key
    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, nullable=False
    )

    # Core attributes
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    integration_type: Mapped[IntegrationType] = mapped_column(
        SQLEnum(IntegrationType, native_enum=False), nullable=False
    )
    system_name: Mapped[str] = mapped_column(String(50), nullable=False)
    owner_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # API endpoint configuration (stored as JSON)
    api_endpoint: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Rate limit configuration (stored as JSON)
    rate_limit: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Capabilities (stored as JSON array)
    capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Additional configuration
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # State fields
    status: Mapped[ConnectionStatus] = mapped_column(
        SQLEnum(ConnectionStatus, native_enum=False),
        nullable=False,
        default=ConnectionStatus.DISCONNECTED,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Health check fields
    last_health_check: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_check_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    credentials: Mapped[list["CredentialModel"]] = relationship(
        "CredentialModel",
        back_populates="integration",
        cascade="all, delete-orphan",
        lazy="select",
    )

    sync_jobs: Mapped[list["SyncJobModel"]] = relationship(
        "SyncJobModel",
        back_populates="integration",
        cascade="all, delete-orphan",
        lazy="select",
    )

    mappings: Mapped[list["MappingModel"]] = relationship(
        "MappingModel",
        back_populates="integration",
        cascade="all, delete-orphan",
        lazy="select",
    )

    webhook_endpoints: Mapped[list["WebhookEndpointModel"]] = relationship(
        "WebhookEndpointModel",
        back_populates="integration",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def to_entity_dict(self) -> dict[str, Any]:
        """Convert model to entity dictionary."""
        return {
            "entity_id": self.id,
            "name": self.name,
            "integration_type": self.integration_type,
            "system_name": self.system_name,
            "api_endpoint": self.api_endpoint,
            "owner_id": self.owner_id,
            "description": self.description,
            "rate_limit": self.rate_limit,
            "capabilities": self.capabilities,
            "configuration": self.configuration,
            "status": self.status,
            "is_active": self.is_active,
            "last_health_check": self.last_health_check,
            "health_check_failures": self.health_check_failures,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
            # Include related entity IDs
            "_credential_ids": [c.id for c in self.credentials],
            "_sync_job_ids": [s.id for s in self.sync_jobs],
            "_mapping_ids": [m.id for m in self.mappings],
            "_webhook_endpoint_ids": [w.id for w in self.webhook_endpoints],
        }

    @classmethod
    def from_entity_dict(cls, data: dict[str, Any]) -> "IntegrationModel":
        """Create model from entity dictionary."""
        # Extract fields that don't map directly
        entity_id = data.pop("entity_id", data.get("id"))
        data.pop("_credential_ids", None)
        data.pop("_sync_job_ids", None)
        data.pop("_mapping_ids", None)
        data.pop("_webhook_endpoint_ids", None)

        # Remove computed properties
        computed_fields = [
            "is_connected",
            "is_healthy",
            "needs_attention",
            "can_sync",
            "can_receive_webhooks",
            "credential_count",
            "sync_job_count",
            "mapping_count",
            "webhook_endpoint_count",
        ]
        for field in computed_fields:
            data.pop(field, None)

        return cls(id=entity_id, **data)

    def __repr__(self) -> str:
        """String representation."""
        return f"<IntegrationModel(id={self.id}, name={self.name}, system={self.system_name})>"
