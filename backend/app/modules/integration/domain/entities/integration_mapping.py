"""Integration mapping entity for field mapping configuration.

This module provides a comprehensive integration mapping entity for
defining how data fields map between different systems.
"""

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.enums import FieldType, MappingTransformation


class IntegrationMapping(Entity):
    """Entity representing field mapping between systems.

    This class manages the configuration for mapping fields between
    source and target systems, including transformations and validation.
    """

    def __init__(
        self,
        integration_id: UUID,
        name: str,
        source_resource: str,
        target_resource: str,
        field_mappings: list[dict[str, Any]],
        is_active: bool = True,
        is_bidirectional: bool = False,
        default_values: dict[str, Any] | None = None,
        validation_rules: list[dict[str, Any]] | None = None,
        transformation_scripts: dict[str, str] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize integration mapping entity.

        Args:
            integration_id: ID of the integration
            name: Name of the mapping
            source_resource: Source resource/entity name
            target_resource: Target resource/entity name
            field_mappings: List of field mapping configurations
            is_active: Whether mapping is active
            is_bidirectional: Whether mapping works both ways
            default_values: Default values for unmapped fields
            validation_rules: Validation rules for mapped data
            transformation_scripts: Custom transformation scripts
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Core attributes
        self.integration_id = integration_id
        self.name = self._validate_name(name)
        self.source_resource = self._validate_resource_name(source_resource, "source")
        self.target_resource = self._validate_resource_name(target_resource, "target")

        # Mapping configuration
        self.field_mappings = self._validate_field_mappings(field_mappings)
        self.is_active = is_active
        self.is_bidirectional = is_bidirectional

        # Additional configuration
        self.default_values = default_values or {}
        self.validation_rules = self._validate_rules(validation_rules or [])
        self.transformation_scripts = transformation_scripts or {}

        # Statistics
        self.usage_count = 0
        self.error_count = 0
        self.last_used_at: datetime | None = None

        # Validate state
        self._validate_entity()

    def _validate_name(self, name: str) -> str:
        """Validate mapping name."""
        if not name or not name.strip():
            raise ValidationError("Mapping name cannot be empty")

        name = name.strip()
        if len(name) > 100:
            raise ValidationError("Mapping name cannot exceed 100 characters")

        return name

    def _validate_resource_name(self, resource: str, resource_type: str) -> str:
        """Validate resource name."""
        if not resource or not resource.strip():
            raise ValidationError(f"{resource_type} resource cannot be empty")

        resource = resource.strip()

        # Allow alphanumeric, underscore, dash, and dot
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", resource):
            raise ValidationError(
                f"{resource_type} resource contains invalid characters"
            )

        return resource

    def _validate_field_mappings(
        self, mappings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Validate field mappings."""
        if not mappings:
            raise ValidationError("At least one field mapping is required")

        if not isinstance(mappings, list):
            raise ValidationError("field_mappings must be a list")

        validated = []
        source_fields = set()

        for idx, mapping in enumerate(mappings):
            if not isinstance(mapping, dict):
                raise ValidationError(f"Mapping at index {idx} must be a dictionary")

            # Validate required fields
            if "source_field" not in mapping:
                raise ValidationError(f"Mapping at index {idx} missing source_field")

            if "target_field" not in mapping:
                raise ValidationError(f"Mapping at index {idx} missing target_field")

            source_field = mapping["source_field"]
            mapping["target_field"]

            # Check for duplicates
            if source_field in source_fields:
                raise ValidationError(
                    f"Duplicate mapping for source field: {source_field}"
                )
            source_fields.add(source_field)

            # Validate field types if provided
            if "source_type" in mapping:
                try:
                    FieldType(mapping["source_type"])
                except ValueError:
                    raise ValidationError(
                        f"Invalid source_type: {mapping['source_type']}"
                    )

            if "target_type" in mapping:
                try:
                    FieldType(mapping["target_type"])
                except ValueError:
                    raise ValidationError(
                        f"Invalid target_type: {mapping['target_type']}"
                    )

            # Validate transformation if provided
            if "transformation" in mapping:
                try:
                    MappingTransformation(mapping["transformation"])
                except ValueError:
                    raise ValidationError(
                        f"Invalid transformation: {mapping['transformation']}"
                    )

            validated.append(mapping.copy())

        return validated

    def _validate_rules(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate validation rules."""
        if not isinstance(rules, list):
            raise ValidationError("validation_rules must be a list")

        validated = []
        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValidationError(f"Rule at index {idx} must be a dictionary")

            if "field" not in rule:
                raise ValidationError(f"Rule at index {idx} missing field")

            if "type" not in rule:
                raise ValidationError(f"Rule at index {idx} missing type")

            validated.append(rule.copy())

        return validated

    def _validate_entity(self) -> None:
        """Validate entity state."""
        super()._validate_entity()

        if not self.integration_id:
            raise ValidationError("integration_id is required")

    @property
    def source_fields(self) -> list[str]:
        """Get list of source fields."""
        return [m["source_field"] for m in self.field_mappings]

    @property
    def target_fields(self) -> list[str]:
        """Get list of target fields."""
        return [m["target_field"] for m in self.field_mappings]

    @property
    def field_count(self) -> int:
        """Get number of field mappings."""
        return len(self.field_mappings)

    @property
    def success_rate(self) -> float:
        """Calculate mapping success rate."""
        total = self.usage_count + self.error_count
        if total == 0:
            return 1.0
        return self.usage_count / total

    @property
    def has_transformations(self) -> bool:
        """Check if mapping has any transformations."""
        for mapping in self.field_mappings:
            if mapping.get("transformation") and mapping["transformation"] != "none":
                return True
        return bool(self.transformation_scripts)

    @property
    def has_validation(self) -> bool:
        """Check if mapping has validation rules."""
        return bool(self.validation_rules)

    def get_mapping_for_source(self, source_field: str) -> dict[str, Any] | None:
        """Get mapping configuration for a source field.

        Args:
            source_field: Source field name

        Returns:
            Mapping configuration or None
        """
        for mapping in self.field_mappings:
            if mapping["source_field"] == source_field:
                return mapping.copy()
        return None

    def get_mapping_for_target(self, target_field: str) -> dict[str, Any] | None:
        """Get mapping configuration for a target field.

        Args:
            target_field: Target field name

        Returns:
            Mapping configuration or None
        """
        for mapping in self.field_mappings:
            if mapping["target_field"] == target_field:
                return mapping.copy()
        return None

    def add_field_mapping(
        self,
        source_field: str,
        target_field: str,
        source_type: FieldType | None = None,
        target_type: FieldType | None = None,
        transformation: MappingTransformation | None = None,
        transformation_params: dict[str, Any] | None = None,
    ) -> None:
        """Add a new field mapping.

        Args:
            source_field: Source field name
            target_field: Target field name
            source_type: Optional source field type
            target_type: Optional target field type
            transformation: Optional transformation
            transformation_params: Optional transformation parameters

        Raises:
            DomainError: If mapping already exists
        """
        # Check for duplicates
        if source_field in self.source_fields:
            raise DomainError(
                f"Mapping for source field '{source_field}' already exists"
            )

        mapping = {"source_field": source_field, "target_field": target_field}

        if source_type:
            mapping["source_type"] = source_type.value

        if target_type:
            mapping["target_type"] = target_type.value

        if transformation:
            mapping["transformation"] = transformation.value
            if transformation_params:
                mapping["transformation_params"] = transformation_params

        self.field_mappings.append(mapping)
        self.mark_modified()

    def remove_field_mapping(self, source_field: str) -> None:
        """Remove a field mapping.

        Args:
            source_field: Source field to remove

        Raises:
            DomainError: If mapping not found
        """
        for idx, mapping in enumerate(self.field_mappings):
            if mapping["source_field"] == source_field:
                self.field_mappings.pop(idx)
                self.mark_modified()
                return

        raise DomainError(f"Mapping for source field '{source_field}' not found")

    def update_field_mapping(self, source_field: str, updates: dict[str, Any]) -> None:
        """Update an existing field mapping.

        Args:
            source_field: Source field to update
            updates: Updates to apply

        Raises:
            DomainError: If mapping not found
        """
        for mapping in self.field_mappings:
            if mapping["source_field"] == source_field:
                # Validate updates
                if (
                    "source_field" in updates
                    and updates["source_field"] != source_field
                ):
                    # Check for conflicts
                    if updates["source_field"] in self.source_fields:
                        raise DomainError("Cannot update to existing source field")

                mapping.update(updates)
                self.mark_modified()
                return

        raise DomainError(f"Mapping for source field '{source_field}' not found")

    def add_validation_rule(
        self,
        field: str,
        rule_type: str,
        params: dict[str, Any],
        error_message: str | None = None,
    ) -> None:
        """Add a validation rule.

        Args:
            field: Field to validate
            rule_type: Type of validation
            params: Validation parameters
            error_message: Optional custom error message
        """
        rule = {"field": field, "type": rule_type, "params": params}

        if error_message:
            rule["error_message"] = error_message

        self.validation_rules.append(rule)
        self.mark_modified()

    def set_default_value(self, field: str, value: Any) -> None:
        """Set default value for a field.

        Args:
            field: Field name
            value: Default value
        """
        self.default_values[field] = value
        self.mark_modified()

    def record_usage(self, success: bool = True) -> None:
        """Record mapping usage.

        Args:
            success: Whether mapping was successful
        """
        if success:
            self.usage_count += 1
        else:
            self.error_count += 1

        self.last_used_at = datetime.now(UTC)
        self.mark_modified()

    def activate(self) -> None:
        """Activate the mapping."""
        if not self.is_active:
            self.is_active = True
            self.mark_modified()

    def deactivate(self) -> None:
        """Deactivate the mapping."""
        if self.is_active:
            self.is_active = False
            self.mark_modified()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        # Add mapping specific fields
        data.update(
            {
                "integration_id": str(self.integration_id),
                "name": self.name,
                "source_resource": self.source_resource,
                "target_resource": self.target_resource,
                "field_mappings": self.field_mappings,
                "is_active": self.is_active,
                "is_bidirectional": self.is_bidirectional,
                "default_values": self.default_values,
                "validation_rules": self.validation_rules,
                "transformation_scripts": list(self.transformation_scripts.keys()),
                "usage_count": self.usage_count,
                "error_count": self.error_count,
                "success_rate": round(self.success_rate, 3),
                "last_used_at": self.last_used_at.isoformat()
                if self.last_used_at
                else None,
                "field_count": self.field_count,
                "has_transformations": self.has_transformations,
                "has_validation": self.has_validation,
                "source_fields": self.source_fields,
                "target_fields": self.target_fields,
            }
        )

        return data

    def __str__(self) -> str:
        """String representation."""
        status = "active" if self.is_active else "inactive"
        direction = "bidirectional" if self.is_bidirectional else "unidirectional"
        return f"IntegrationMapping({self.name}, {self.source_resource}->{self.target_resource}, {self.field_count} fields, {status}, {direction})"
