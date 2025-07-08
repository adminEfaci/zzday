"""Credential database model with encryption support.

This module provides the SQLAlchemy model for API credentials with
encrypted storage for sensitive data.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.infrastructure.database import Base, UtcTimestampMixin


class CredentialModel(Base, UtcTimestampMixin):
    """SQLAlchemy model for API credentials with encryption."""

    __tablename__ = "integration_credentials"
    __table_args__ = (
        Index("idx_credentials_integration_id", "integration_id"),
        Index("idx_credentials_active", "is_active"),
        Index("idx_credentials_auth_type", "auth_type"),
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
    auth_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Encrypted credential storage
    encrypted_credentials: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(100), nullable=False)

    # OAuth specific fields (encrypted separately)
    encrypted_token_endpoint: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    scopes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    encrypted_refresh_token: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )

    # Custom headers (non-sensitive)
    custom_headers: Mapped[dict[str, str]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # State fields
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Usage tracking
    last_used_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_rotated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    rotation_period_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Additional metadata
    metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    integration: Mapped["IntegrationModel"] = relationship(
        "IntegrationModel", back_populates="credentials", lazy="select"
    )

    def to_entity_dict(self) -> dict[str, Any]:
        """Convert model to entity dictionary (without decrypting credentials)."""
        return {
            "entity_id": self.id,
            "integration_id": self.integration_id,
            "name": self.name,
            "auth_type": self.auth_type,
            "is_active": self.is_active,
            "last_used_at": self.last_used_at,
            "last_rotated_at": self.last_rotated_at,
            "rotation_period_days": self.rotation_period_days,
            "usage_count": self.usage_count,
            "failure_count": self.failure_count,
            "metadata": self.metadata,
            "expires_at": self.expires_at,
            "scopes": self.scopes,
            "custom_headers": self.custom_headers,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
            "_encryption_key_id": self.encryption_key_id,
            # Indicate that credentials exist but are encrypted
            "_has_encrypted_credentials": True,
            "_has_encrypted_token_endpoint": bool(self.encrypted_token_endpoint),
            "_has_encrypted_refresh_token": bool(self.encrypted_refresh_token),
        }

    @classmethod
    def from_entity_dict(
        cls, data: dict[str, Any], encrypted_data: dict[str, bytes]
    ) -> "CredentialModel":
        """Create model from entity dictionary with encrypted data.

        Args:
            data: Entity dictionary
            encrypted_data: Dictionary with encrypted fields:
                - encrypted_credentials
                - encrypted_token_endpoint (optional)
                - encrypted_refresh_token (optional)
        """
        # Extract fields
        entity_id = data.pop("entity_id", data.get("id"))
        encryption_key_id = data.pop(
            "_encryption_key_id", data.get("encryption_key_id")
        )

        # Remove computed/internal fields
        data.pop("_has_encrypted_credentials", None)
        data.pop("_has_encrypted_token_endpoint", None)
        data.pop("_has_encrypted_refresh_token", None)
        data.pop("auth_method", None)  # This is reconstructed from encrypted data
        data.pop("is_expired", None)
        data.pop("needs_rotation", None)
        data.pop("is_healthy", None)
        data.pop("failure_rate", None)
        data.pop("days_since_rotation", None)
        data.pop("has_credentials", None)

        return cls(
            id=entity_id,
            encryption_key_id=encryption_key_id,
            encrypted_credentials=encrypted_data["encrypted_credentials"],
            encrypted_token_endpoint=encrypted_data.get("encrypted_token_endpoint"),
            encrypted_refresh_token=encrypted_data.get("encrypted_refresh_token"),
            **data,
        )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<CredentialModel(id={self.id}, name={self.name}, type={self.auth_type})>"
        )
