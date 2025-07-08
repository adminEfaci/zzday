"""Integration mapping database model.

This module provides the SQLAlchemy model for field mappings.
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
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.infrastructure.database import Base, UtcTimestampMixin
from app.modules.integration.domain.enums import FieldType, MappingTransformation


class MappingModel(Base, UtcTimestampMixin):
    """SQLAlchemy model for integration field mappings."""

    __tablename__ = "integration_mappings"
    __table_args__ = (
        UniqueConstraint(
            "integration_id",
            "source_field",
            "target_field",
            name="uq_mappings_integration_source_target",
        ),
        Index("idx_mappings_integration_id", "integration_id"),
        Index("idx_mappings_active", "is_active"),
        Index("idx_mappings_entity_type", "entity_type"),
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
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Field mapping
    source_field: Mapped[str] = mapped_column(String(255), nullable=False)
    target_field: Mapped[str] = mapped_column(String(255), nullable=False)

    # Field types
    source_type: Mapped[FieldType] = mapped_column(
        SQLEnum(FieldType, native_enum=False), nullable=False
    )
    target_type: Mapped[FieldType] = mapped_column(
        SQLEnum(FieldType, native_enum=False), nullable=False
    )

    # Transformation
    transformation: Mapped[MappingTransformation] = mapped_column(
        SQLEnum(MappingTransformation, native_enum=False),
        nullable=False,
        default=MappingTransformation.NONE,
    )
    transformation_config: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )

    # Custom transformation script (for complex mappings)
    custom_script: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Validation rules
    validation_rules: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )

    # Default value configuration
    default_value: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    use_default_on_error: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # State
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Additional metadata
    metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Optimistic locking
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    integration: Mapped["IntegrationModel"] = relationship(
        "IntegrationModel", back_populates="mappings", lazy="select"
    )

    def to_entity_dict(self) -> dict[str, Any]:
        """Convert model to entity dictionary."""
        return {
            "entity_id": self.id,
            "integration_id": self.integration_id,
            "name": self.name,
            "description": self.description,
            "entity_type": self.entity_type,
            "source_field": self.source_field,
            "target_field": self.target_field,
            "source_type": self.source_type,
            "target_type": self.target_type,
            "transformation": self.transformation,
            "transformation_config": self.transformation_config,
            "custom_script": self.custom_script,
            "validation_rules": self.validation_rules,
            "default_value": self.default_value,
            "use_default_on_error": self.use_default_on_error,
            "is_active": self.is_active,
            "is_required": self.is_required,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }

    @classmethod
    def from_entity_dict(cls, data: dict[str, Any]) -> "MappingModel":
        """Create model from entity dictionary."""
        # Extract fields
        entity_id = data.pop("entity_id", data.get("id"))

        # Remove computed fields
        computed_fields = [
            "requires_transformation",
            "has_validation",
            "is_type_compatible",
        ]
        for field in computed_fields:
            data.pop(field, None)

        return cls(id=entity_id, **data)

    def __repr__(self) -> str:
        """String representation."""
        return f"<MappingModel(id={self.id}, name={self.name}, {self.source_field}->{self.target_field})>"
