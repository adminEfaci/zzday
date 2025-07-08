"""Data transformation service for field mappings.

This module provides data transformation functionality for
converting between different data formats and field mappings.
"""

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from app.core.errors import ValidationError
from app.modules.integration.domain.entities import IntegrationMapping
from app.modules.integration.domain.enums import FieldType, MappingTransformation

logger = logging.getLogger(__name__)


class DataTransformationService:
    """Service for transforming data between systems."""

    def __init__(self):
        """Initialize transformation service."""
        # Built-in transformations
        self._transformations: dict[MappingTransformation, Callable] = {
            MappingTransformation.NONE: self._transform_none,
            MappingTransformation.UPPERCASE: self._transform_uppercase,
            MappingTransformation.LOWERCASE: self._transform_lowercase,
            MappingTransformation.TRIM: self._transform_trim,
            MappingTransformation.DATE_FORMAT: self._transform_date_format,
            MappingTransformation.NUMBER_FORMAT: self._transform_number_format,
            MappingTransformation.CUSTOM: self._transform_custom,
        }

        # Type converters
        self._type_converters: dict[tuple[FieldType, FieldType], Callable] = {
            (FieldType.STRING, FieldType.INTEGER): self._convert_string_to_int,
            (FieldType.STRING, FieldType.FLOAT): self._convert_string_to_float,
            (FieldType.STRING, FieldType.BOOLEAN): self._convert_string_to_bool,
            (FieldType.STRING, FieldType.DATETIME): self._convert_string_to_datetime,
            (FieldType.INTEGER, FieldType.STRING): self._convert_int_to_string,
            (FieldType.FLOAT, FieldType.STRING): self._convert_float_to_string,
            (FieldType.BOOLEAN, FieldType.STRING): self._convert_bool_to_string,
            (FieldType.DATETIME, FieldType.STRING): self._convert_datetime_to_string,
            # Add more converters as needed
        }

    async def transform_record(
        self,
        source_data: dict[str, Any],
        mappings: list[IntegrationMapping],
        direction: str = "import",
    ) -> dict[str, Any]:
        """Transform a record using field mappings.

        Args:
            source_data: Source data record
            mappings: Field mappings to apply
            direction: Transformation direction

        Returns:
            Transformed record
        """
        transformed = {}
        errors = []

        for mapping in mappings:
            if not mapping.is_active:
                continue

            try:
                # Get source value
                if direction == "import":
                    source_value = self._get_nested_value(
                        source_data, mapping.source_field
                    )
                else:
                    source_value = self._get_nested_value(
                        source_data, mapping.target_field
                    )

                # Apply transformation
                transformed_value = await self.transform_field(
                    source_value, mapping, direction
                )

                # Set target value
                if direction == "import":
                    self._set_nested_value(
                        transformed, mapping.target_field, transformed_value
                    )
                else:
                    self._set_nested_value(
                        transformed, mapping.source_field, transformed_value
                    )

            except Exception as e:
                error_msg = f"Field transformation failed for {mapping.name}: {e!s}"
                logger.exception(error_msg)
                errors.append(error_msg)

                # Use default value if configured
                if mapping.use_default_on_error and mapping.default_value is not None:
                    if direction == "import":
                        self._set_nested_value(
                            transformed, mapping.target_field, mapping.default_value
                        )
                    else:
                        self._set_nested_value(
                            transformed, mapping.source_field, mapping.default_value
                        )

        if errors:
            transformed["_transformation_errors"] = errors

        return transformed

    async def transform_field(
        self, value: Any, mapping: IntegrationMapping, direction: str = "import"
    ) -> Any:
        """Transform a single field value.

        Args:
            value: Source value
            mapping: Field mapping
            direction: Transformation direction

        Returns:
            Transformed value
        """
        # Handle None/null values
        if value is None:
            if mapping.is_required and mapping.default_value is None:
                raise ValidationError(f"Required field {mapping.name} is null")
            return mapping.default_value

        # Type conversion if needed
        if direction == "import":
            source_type = mapping.source_type
            target_type = mapping.target_type
        else:
            source_type = mapping.target_type
            target_type = mapping.source_type

        if source_type != target_type:
            converter = self._type_converters.get((source_type, target_type))
            if converter:
                value = converter(value)
            elif not self._is_compatible_type(source_type, target_type):
                raise ValidationError(
                    f"Cannot convert {source_type.value} to {target_type.value}"
                )

        # Apply transformation
        transformation_func = self._transformations.get(mapping.transformation)
        if transformation_func:
            value = transformation_func(value, mapping.transformation_config)

        # Validate result
        self._validate_value(value, target_type, mapping.validation_rules)

        return value

    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        parts = path.split(".")
        value = data

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None

        return value

    def _set_nested_value(self, data: dict[str, Any], path: str, value: Any) -> None:
        """Set value in nested dictionary using dot notation."""
        parts = path.split(".")
        current = data

        for _i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    def _transform_none(self, value: Any, config: dict[str, Any] | None) -> Any:
        """No transformation."""
        return value

    def _transform_uppercase(self, value: Any, config: dict[str, Any] | None) -> Any:
        """Convert to uppercase."""
        return str(value).upper() if value is not None else None

    def _transform_lowercase(self, value: Any, config: dict[str, Any] | None) -> Any:
        """Convert to lowercase."""
        return str(value).lower() if value is not None else None

    def _transform_trim(self, value: Any, config: dict[str, Any] | None) -> Any:
        """Trim whitespace."""
        return str(value).strip() if value is not None else None

    def _transform_date_format(self, value: Any, config: dict[str, Any] | None) -> Any:
        """Transform date format."""
        if not config:
            return value

        input_format = config.get("input_format", "%Y-%m-%d")
        output_format = config.get("output_format", "%Y-%m-%d")

        if isinstance(value, str):
            dt = datetime.strptime(value, input_format)
        elif isinstance(value, datetime):
            dt = value
        else:
            return value

        return dt.strftime(output_format)

    def _transform_number_format(
        self, value: Any, config: dict[str, Any] | None
    ) -> Any:
        """Transform number format."""
        if not config:
            return value

        precision = config.get("precision", 2)

        if isinstance(value, int | float | Decimal):
            return round(float(value), precision)

        return value

    def _transform_custom(self, value: Any, config: dict[str, Any] | None) -> Any:
        """Custom transformation using script."""
        if not config or "script" not in config:
            return value

        # Execute custom script (simplified)
        # In production, use sandboxed execution
        script = config["script"]

        # Create safe context
        context = {"value": value, "datetime": datetime, "json": json, "re": re}

        try:
            exec(script, context)
            return context.get("result", value)
        except Exception as e:
            logger.exception(f"Custom transformation failed: {e}")
            raise

    def _convert_string_to_int(self, value: str) -> int:
        """Convert string to integer."""
        return int(value)

    def _convert_string_to_float(self, value: str) -> float:
        """Convert string to float."""
        return float(value)

    def _convert_string_to_bool(self, value: str) -> bool:
        """Convert string to boolean."""
        return value.lower() in ("true", "1", "yes", "on")

    def _convert_string_to_datetime(self, value: str) -> datetime:
        """Convert string to datetime."""
        # Try common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue

        # ISO format
        return datetime.fromisoformat(value)

    def _convert_int_to_string(self, value: int) -> str:
        """Convert integer to string."""
        return str(value)

    def _convert_float_to_string(self, value: float) -> str:
        """Convert float to string."""
        return str(value)

    def _convert_bool_to_string(self, value: bool) -> str:
        """Convert boolean to string."""
        return "true" if value else "false"

    def _convert_datetime_to_string(self, value: datetime) -> str:
        """Convert datetime to string."""
        return value.isoformat()

    def _is_compatible_type(
        self, source_type: FieldType, target_type: FieldType
    ) -> bool:
        """Check if types are compatible for conversion."""
        # Check if converter exists
        return (source_type, target_type) in self._type_converters

    def _validate_value(
        self, value: Any, field_type: FieldType, rules: list[dict[str, Any]]
    ) -> None:
        """Validate value against rules."""
        for rule in rules:
            rule_type = rule.get("type")

            if rule_type == "required" and value is None:
                raise ValidationError("Value is required")

            if rule_type == "min_length" and isinstance(value, str):
                min_len = rule.get("value", 0)
                if len(value) < min_len:
                    raise ValidationError(f"Value length must be at least {min_len}")

            elif rule_type == "max_length" and isinstance(value, str):
                max_len = rule.get("value", 0)
                if len(value) > max_len:
                    raise ValidationError(f"Value length must not exceed {max_len}")

            elif rule_type == "pattern" and isinstance(value, str):
                pattern = rule.get("value")
                if pattern and not re.match(pattern, value):
                    raise ValidationError(f"Value does not match pattern: {pattern}")

            elif rule_type == "min" and isinstance(value, int | float):
                min_val = rule.get("value", 0)
                if value < min_val:
                    raise ValidationError(f"Value must be at least {min_val}")

            elif rule_type == "max" and isinstance(value, int | float):
                max_val = rule.get("value", 0)
                if value > max_val:
                    raise ValidationError(f"Value must not exceed {max_val}")

    async def transform_webhook_payload(
        self, payload: dict[str, Any], event_type: str
    ) -> dict[str, Any]:
        """Transform webhook payload based on event type."""
        # Event-specific transformations
        # Implementation depends on specific requirements
        return payload
