"""Transformation specification value object for data transformations.

This module provides the TransformationSpec value object that defines
detailed specifications for complex data transformations.
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


@dataclass(frozen=True)
class TransformationSpec(ValueObject):
    """Value object representing a transformation specification.

    This immutable object defines detailed specifications for
    transforming data between different formats and structures.
    """

    # Basic information
    name: str
    description: str
    version: str = "1.0.0"

    # Transformation definition
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)

    # Transformation steps
    steps: list[dict[str, Any]] = field(default_factory=list)

    # Script-based transformations
    transform_script: str | None = None
    script_language: str = "python"  # python, javascript, jmespath

    # Error handling
    error_handling: str = "fail"  # fail, skip, default
    error_defaults: dict[str, Any] = field(default_factory=dict)

    # Performance settings
    batch_capable: bool = False
    max_batch_size: int = 100
    timeout_seconds: int = 30

    # Validation rules
    pre_validation: list[dict[str, Any]] = field(default_factory=list)
    post_validation: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate transformation spec after initialization."""
        self._validate_spec()

    def _validate_spec(self) -> None:
        """Validate the transformation specification."""
        # Validate name
        if not self.name:
            raise ValidationError("Transformation name is required")

        if not self.name.replace("_", "").replace("-", "").isalnum():
            raise ValidationError(
                "Transformation name must be alphanumeric with underscores/hyphens"
            )

        # Validate version format
        version_parts = self.version.split(".")
        if len(version_parts) != 3:
            raise ValidationError("Version must be in format X.Y.Z")

        try:
            for part in version_parts:
                int(part)
        except ValueError:
            raise ValidationError("Version parts must be numeric")

        # Validate schemas
        if not self.input_schema:
            raise ValidationError("Input schema is required")

        if not self.output_schema:
            raise ValidationError("Output schema is required")

        # Validate error handling
        valid_error_handling = {"fail", "skip", "default"}
        if self.error_handling not in valid_error_handling:
            raise ValidationError(
                f"Invalid error handling: {self.error_handling}. "
                f"Must be one of: {', '.join(valid_error_handling)}"
            )

        # Validate script language
        valid_languages = {"python", "javascript", "jmespath"}
        if self.script_language not in valid_languages:
            raise ValidationError(
                f"Invalid script language: {self.script_language}. "
                f"Must be one of: {', '.join(valid_languages)}"
            )

        # Validate transform script if present
        if self.transform_script:
            self._validate_transform_script()

        # Validate steps
        if self.steps:
            self._validate_steps()

        # Validate performance settings
        if self.max_batch_size <= 0:
            raise ValidationError("Max batch size must be positive")

        if self.timeout_seconds <= 0:
            raise ValidationError("Timeout must be positive")

    def _validate_transform_script(self) -> None:
        """Validate the transformation script syntax."""
        if not self.transform_script:
            return

        if self.script_language == "python":
            try:
                # Basic syntax check for Python
                ast.parse(self.transform_script)
            except SyntaxError as e:
                raise ValidationError(f"Invalid Python syntax in transform script: {e}")

        # Additional language-specific validation can be added here

    def _validate_steps(self) -> None:
        """Validate transformation steps."""
        for i, step in enumerate(self.steps):
            if "type" not in step:
                raise ValidationError(f"Step {i} missing required 'type' field")

            step_type = step["type"]
            valid_step_types = {
                "map",
                "filter",
                "aggregate",
                "join",
                "split",
                "rename",
                "convert",
                "validate",
                "custom",
            }

            if step_type not in valid_step_types:
                raise ValidationError(
                    f"Invalid step type '{step_type}' in step {i}. "
                    f"Must be one of: {', '.join(valid_step_types)}"
                )

            # Validate step-specific requirements
            if step_type == "map" and "mapping" not in step:
                raise ValidationError(f"Map step {i} missing required 'mapping' field")

            if step_type == "filter" and "condition" not in step:
                raise ValidationError(
                    f"Filter step {i} missing required 'condition' field"
                )

    @property
    def is_script_based(self) -> bool:
        """Check if transformation is script-based."""
        return bool(self.transform_script)

    @property
    def is_step_based(self) -> bool:
        """Check if transformation is step-based."""
        return bool(self.steps)

    @property
    def requires_validation(self) -> bool:
        """Check if transformation requires validation."""
        return bool(self.pre_validation or self.post_validation)

    @property
    def supports_batching(self) -> bool:
        """Check if transformation supports batch processing."""
        return self.batch_capable and self.max_batch_size > 1

    def get_input_fields(self) -> list[str]:
        """Extract input field names from schema.

        Returns:
            List of input field names
        """
        if "properties" in self.input_schema:
            return list(self.input_schema["properties"].keys())
        if "fields" in self.input_schema:
            return [f["name"] for f in self.input_schema["fields"]]
        return []

    def get_output_fields(self) -> list[str]:
        """Extract output field names from schema.

        Returns:
            List of output field names
        """
        if "properties" in self.output_schema:
            return list(self.output_schema["properties"].keys())
        if "fields" in self.output_schema:
            return [f["name"] for f in self.output_schema["fields"]]
        return []

    def get_step_by_name(self, name: str) -> dict[str, Any] | None:
        """Get a transformation step by name.

        Args:
            name: Step name to find

        Returns:
            Step configuration if found, None otherwise
        """
        for step in self.steps:
            if step.get("name") == name:
                return step
        return None

    def validate_input(self, data: dict[str, Any]) -> list[str]:
        """Validate input data against schema.

        Args:
            data: Input data to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        required_fields = self.input_schema.get("required", [])
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        # Check field types if schema defines them
        if "properties" in self.input_schema:
            for field, schema in self.input_schema["properties"].items():
                if field in data:
                    value = data[field]
                    expected_type = schema.get("type")

                    if expected_type and not self._check_type(value, expected_type):
                        errors.append(
                            f"Field '{field}' has incorrect type. "
                            f"Expected: {expected_type}"
                        )

        # Run pre-validation rules
        for rule in self.pre_validation:
            if not self._evaluate_validation_rule(rule, data):
                errors.append(
                    f"Validation failed: {rule.get('message', 'Unknown error')}"
                )

        return errors

    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Check if value matches expected type.

        Args:
            value: Value to check
            expected_type: Expected type name

        Returns:
            True if type matches, False otherwise
        """
        type_map = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "array": list,
            "object": dict,
        }

        expected_python_type = type_map.get(expected_type)
        if expected_python_type:
            return isinstance(value, expected_python_type)

        return True

    def _evaluate_validation_rule(
        self, rule: dict[str, Any], data: dict[str, Any]
    ) -> bool:
        """Evaluate a validation rule against data.

        Args:
            rule: Validation rule configuration
            data: Data to validate

        Returns:
            True if validation passes, False otherwise
        """
        rule_type = rule.get("type")

        if rule_type == "required":
            field = rule.get("field")
            return field in data and data[field] is not None

        if rule_type == "range":
            field = rule.get("field")
            min_val = rule.get("min")
            max_val = rule.get("max")

            if field in data:
                value = data[field]
                if min_val is not None and value < min_val:
                    return False
                if max_val is not None and value > max_val:
                    return False

        elif rule_type == "pattern":
            field = rule.get("field")
            pattern = rule.get("pattern")

            if field in data:
                import re

                return bool(re.match(pattern, str(data[field])))

        elif rule_type == "custom":
            # Custom validation would be handled externally
            return True

        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the transformation spec
        """
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "steps": self.steps,
            "transform_script": self.transform_script,
            "script_language": self.script_language,
            "error_handling": self.error_handling,
            "error_defaults": self.error_defaults,
            "batch_capable": self.batch_capable,
            "max_batch_size": self.max_batch_size,
            "timeout_seconds": self.timeout_seconds,
            "pre_validation": self.pre_validation,
            "post_validation": self.post_validation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TransformationSpec":
        """Create from dictionary representation.

        Args:
            data: Dictionary containing transformation spec data

        Returns:
            TransformationSpec instance
        """
        return cls(
            name=data["name"],
            description=data["description"],
            version=data.get("version", "1.0.0"),
            input_schema=data.get("input_schema", {}),
            output_schema=data.get("output_schema", {}),
            steps=data.get("steps", []),
            transform_script=data.get("transform_script"),
            script_language=data.get("script_language", "python"),
            error_handling=data.get("error_handling", "fail"),
            error_defaults=data.get("error_defaults", {}),
            batch_capable=data.get("batch_capable", False),
            max_batch_size=data.get("max_batch_size", 100),
            timeout_seconds=data.get("timeout_seconds", 30),
            pre_validation=data.get("pre_validation", []),
            post_validation=data.get("post_validation", []),
        )

    @classmethod
    def create_simple_mapping(
        cls, name: str, field_mappings: dict[str, str], description: str = ""
    ) -> "TransformationSpec":
        """Create a simple field mapping transformation.

        Args:
            name: Transformation name
            field_mappings: Dictionary of source to target field mappings
            description: Optional description

        Returns:
            TransformationSpec instance for simple mapping
        """
        # Build schemas from mappings
        input_properties = {field: {"type": "string"} for field in field_mappings}
        output_properties = {
            field: {"type": "string"} for field in field_mappings.values()
        }

        # Create mapping step
        mapping_step = {
            "type": "map",
            "name": "field_mapping",
            "mapping": field_mappings,
        }

        return cls(
            name=name,
            description=description or f"Simple field mapping: {name}",
            input_schema={"type": "object", "properties": input_properties},
            output_schema={"type": "object", "properties": output_properties},
            steps=[mapping_step],
        )
