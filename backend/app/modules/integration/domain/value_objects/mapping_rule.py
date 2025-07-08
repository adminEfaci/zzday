"""Mapping rule value object for field transformation rules.

This module provides the MappingRule value object that defines
how fields are mapped and transformed between systems.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.modules.integration.domain.enums import (
    FieldType,
    MappingTransformation,
    MappingType,
)


@dataclass(frozen=True)
class MappingRule(ValueObject):
    """Value object representing a field mapping rule.

    This immutable object defines how a field from one system
    is mapped and transformed to a field in another system.
    """

    # Source and target fields
    source_field: str
    target_field: str

    # Mapping configuration
    mapping_type: MappingType
    source_type: FieldType
    target_type: FieldType

    # Transformation settings
    transformation: MappingTransformation = MappingTransformation.NONE
    transformation_params: dict[str, Any] = field(default_factory=dict)

    # Validation and defaults
    is_required: bool = False
    default_value: Any | None = None
    validation_pattern: str | None = None

    # Advanced settings
    custom_script: str | None = None
    conditions: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate mapping rule after initialization."""
        self._validate_rule()

    def _validate_rule(self) -> None:
        """Validate the mapping rule configuration."""
        # Validate field names
        if not self.source_field and self.mapping_type != MappingType.CONSTANT:
            raise ValidationError("Source field is required for non-constant mappings")

        if not self.target_field:
            raise ValidationError("Target field is required")

        # Validate field name format
        field_pattern = r"^[a-zA-Z][a-zA-Z0-9_\.]*$"
        if self.source_field and not re.match(field_pattern, self.source_field):
            raise ValidationError(f"Invalid source field name: {self.source_field}")

        if not re.match(field_pattern, self.target_field):
            raise ValidationError(f"Invalid target field name: {self.target_field}")

        # Validate transformation compatibility
        if self.transformation != MappingTransformation.NONE:
            self._validate_transformation()

        # Validate validation pattern
        if self.validation_pattern:
            try:
                re.compile(self.validation_pattern)
            except re.error as e:
                raise ValidationError(f"Invalid validation pattern: {e}")

        # Validate default value type
        if self.default_value is not None:
            self._validate_default_value()

        # Validate custom script if present
        if self.custom_script and self.mapping_type != MappingType.COMPUTED:
            raise ValidationError("Custom script is only allowed for computed mappings")

    def _validate_transformation(self) -> None:
        """Validate transformation compatibility with field types."""
        # String transformations
        string_transforms = {
            MappingTransformation.UPPERCASE,
            MappingTransformation.LOWERCASE,
            MappingTransformation.TRIM,
        }

        if self.transformation in string_transforms:
            if self.source_type != FieldType.STRING:
                raise ValidationError(
                    f"Transformation {self.transformation} requires string source type"
                )

        # Date transformations
        if self.transformation == MappingTransformation.DATE_FORMAT:
            if not self.source_type.is_temporal:
                raise ValidationError(
                    "Date format transformation requires temporal source type"
                )
            if "format" not in self.transformation_params:
                raise ValidationError(
                    "Date format transformation requires 'format' parameter"
                )

        # Number transformations
        if self.transformation == MappingTransformation.NUMBER_FORMAT:
            if not self.source_type.is_numeric:
                raise ValidationError(
                    "Number format transformation requires numeric source type"
                )

    def _validate_default_value(self) -> None:
        """Validate default value matches target type."""
        if self.target_type == FieldType.STRING and not isinstance(
            self.default_value, str
        ):
            raise ValidationError("Default value must be string for string target type")

        if self.target_type == FieldType.INTEGER:
            if not isinstance(self.default_value, int):
                raise ValidationError(
                    "Default value must be integer for integer target type"
                )

        elif self.target_type == FieldType.FLOAT:
            if not isinstance(self.default_value, int | float):
                raise ValidationError(
                    "Default value must be numeric for float target type"
                )

        elif self.target_type == FieldType.BOOLEAN:
            if not isinstance(self.default_value, bool):
                raise ValidationError(
                    "Default value must be boolean for boolean target type"
                )

    @property
    def requires_transformation(self) -> bool:
        """Check if the mapping requires transformation."""
        return (
            self.transformation != MappingTransformation.NONE
            or self.source_type != self.target_type
            or self.mapping_type in {MappingType.TRANSFORMED, MappingType.COMPUTED}
        )

    @property
    def is_direct_mapping(self) -> bool:
        """Check if this is a direct field mapping."""
        return (
            self.mapping_type == MappingType.DIRECT
            and self.transformation == MappingTransformation.NONE
            and self.source_type == self.target_type
        )

    @property
    def has_conditions(self) -> bool:
        """Check if the mapping has conditions."""
        return bool(self.conditions)

    @property
    def has_validation(self) -> bool:
        """Check if the mapping has validation rules."""
        return bool(self.validation_pattern)

    def apply_transformation(self, value: Any) -> Any:
        """Apply the configured transformation to a value.

        Args:
            value: The value to transform

        Returns:
            Transformed value

        Raises:
            ValidationError: If transformation fails
        """
        if value is None and self.default_value is not None:
            return self.default_value

        if value is None:
            return None

        try:
            # Apply transformations based on type
            if self.transformation == MappingTransformation.NONE:
                return value

            if self.transformation == MappingTransformation.UPPERCASE:
                return str(value).upper()

            if self.transformation == MappingTransformation.LOWERCASE:
                return str(value).lower()

            if self.transformation == MappingTransformation.TRIM:
                return str(value).strip()

            if self.transformation == MappingTransformation.DATE_FORMAT:
                # This would typically use a date parsing library
                # For now, return as-is
                return value

            if self.transformation == MappingTransformation.NUMBER_FORMAT:
                # Apply number formatting
                precision = self.transformation_params.get("precision", 2)
                return round(float(value), precision)

            if self.transformation == MappingTransformation.CUSTOM:
                # Custom transformation would be handled by external processor
                return value

            return value

        except Exception as e:
            raise ValidationError(f"Transformation failed: {e!s}")

    def validate_value(self, value: Any) -> bool:
        """Validate a value against the mapping rules.

        Args:
            value: The value to validate

        Returns:
            True if valid, False otherwise
        """
        # Check required field
        if self.is_required and value is None:
            return False

        # Check validation pattern
        if self.validation_pattern and value is not None:
            if not re.match(self.validation_pattern, str(value)):
                return False

        # Type-specific validation
        try:
            if self.target_type == FieldType.INTEGER and value is not None:
                int(value)
            elif self.target_type == FieldType.FLOAT and value is not None:
                float(value)
            elif self.target_type == FieldType.BOOLEAN and value is not None:
                if not isinstance(value, bool):
                    return False
        except (ValueError, TypeError):
            return False

        return True

    def evaluate_conditions(self, context: dict[str, Any]) -> bool:
        """Evaluate mapping conditions against context.

        Args:
            context: Context dictionary with values to evaluate

        Returns:
            True if all conditions pass, False otherwise
        """
        if not self.conditions:
            return True

        for condition in self.conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            if field not in context:
                return False

            context_value = context[field]

            # Evaluate condition based on operator
            if (operator == "equals" and context_value != value) or (
                operator == "not_equals" and context_value == value
            ):
                return False
            if (
                (operator == "contains" and value not in str(context_value))
                or (operator == "greater_than" and context_value <= value)
                or (operator == "less_than" and context_value >= value)
            ):
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the mapping rule
        """
        return {
            "source_field": self.source_field,
            "target_field": self.target_field,
            "mapping_type": self.mapping_type.value,
            "source_type": self.source_type.value,
            "target_type": self.target_type.value,
            "transformation": self.transformation.value,
            "transformation_params": self.transformation_params,
            "is_required": self.is_required,
            "default_value": self.default_value,
            "validation_pattern": self.validation_pattern,
            "custom_script": self.custom_script,
            "conditions": self.conditions,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MappingRule":
        """Create from dictionary representation.

        Args:
            data: Dictionary containing mapping rule data

        Returns:
            MappingRule instance
        """
        return cls(
            source_field=data["source_field"],
            target_field=data["target_field"],
            mapping_type=MappingType(data["mapping_type"]),
            source_type=FieldType(data["source_type"]),
            target_type=FieldType(data["target_type"]),
            transformation=MappingTransformation(data.get("transformation", "none")),
            transformation_params=data.get("transformation_params", {}),
            is_required=data.get("is_required", False),
            default_value=data.get("default_value"),
            validation_pattern=data.get("validation_pattern"),
            custom_script=data.get("custom_script"),
            conditions=data.get("conditions", []),
        )

    @classmethod
    def create_direct(
        cls,
        source_field: str,
        target_field: str,
        field_type: FieldType,
        is_required: bool = False,
    ) -> "MappingRule":
        """Create a direct mapping rule.

        Args:
            source_field: Source field name
            target_field: Target field name
            field_type: Field type for both source and target
            is_required: Whether the field is required

        Returns:
            Direct MappingRule instance
        """
        return cls(
            source_field=source_field,
            target_field=target_field,
            mapping_type=MappingType.DIRECT,
            source_type=field_type,
            target_type=field_type,
            transformation=MappingTransformation.NONE,
            is_required=is_required,
        )
