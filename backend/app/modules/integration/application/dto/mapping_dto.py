"""Mapping DTOs for application layer.

This module provides data transfer objects for integration mapping data,
ensuring clean interfaces for field mapping operations.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.enums import FieldType, MappingTransformation


@dataclass(frozen=True)
class FieldMappingDTO:
    """DTO for individual field mapping."""

    source_field: str
    target_field: str
    field_type: FieldType
    transformation: MappingTransformation
    transformation_config: dict[str, Any]
    is_required: bool
    default_value: Any | None
    validation_rules: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_field": self.source_field,
            "target_field": self.target_field,
            "field_type": self.field_type.value,
            "transformation": self.transformation.value,
            "transformation_config": self.transformation_config,
            "is_required": self.is_required,
            "default_value": self.default_value,
            "validation_rules": self.validation_rules,
        }


@dataclass(frozen=True)
class MappingConfigDTO:
    """DTO for mapping configuration data."""

    mapping_id: UUID
    integration_id: UUID
    name: str
    description: str | None
    source_entity: str
    target_entity: str
    field_mappings: list[FieldMappingDTO]
    filters: dict[str, Any]
    options: dict[str, Any]
    is_active: bool
    created_by: UUID
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_domain(cls, mapping: Any) -> "MappingConfigDTO":
        """Create DTO from domain model."""
        field_mappings = []
        for field_map in mapping.field_mappings:
            field_mappings.append(
                FieldMappingDTO(
                    source_field=field_map["source_field"],
                    target_field=field_map["target_field"],
                    field_type=FieldType(field_map["field_type"]),
                    transformation=MappingTransformation(field_map["transformation"]),
                    transformation_config=field_map.get("transformation_config", {}),
                    is_required=field_map.get("is_required", False),
                    default_value=field_map.get("default_value"),
                    validation_rules=field_map.get("validation_rules", []),
                )
            )

        return cls(
            mapping_id=mapping.id,
            integration_id=mapping.integration_id,
            name=mapping.name,
            description=mapping.description,
            source_entity=mapping.source_entity,
            target_entity=mapping.target_entity,
            field_mappings=field_mappings,
            filters=mapping.filters,
            options=mapping.options,
            is_active=mapping.is_active,
            created_by=mapping.created_by,
            created_at=mapping.created_at,
            updated_at=mapping.updated_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mapping_id": str(self.mapping_id),
            "integration_id": str(self.integration_id),
            "name": self.name,
            "description": self.description,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "field_mappings": [fm.to_dict() for fm in self.field_mappings],
            "filters": self.filters,
            "options": self.options,
            "is_active": self.is_active,
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True)
class MappingValidationResultDTO:
    """DTO for mapping validation results."""

    mapping_id: UUID
    is_valid: bool
    errors: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    tested_records: int
    successful_mappings: int
    failed_mappings: int
    validation_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mapping_id": str(self.mapping_id),
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "tested_records": self.tested_records,
            "successful_mappings": self.successful_mappings,
            "failed_mappings": self.failed_mappings,
            "validation_time_ms": self.validation_time_ms,
        }
