"""Mapping application service.

This module provides the application service for data mapping management,
including field mapping validation and transformation logic.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import (
    MappingConfigDTO,
    MappingValidationResultDTO,
)
from app.modules.integration.domain.entities import IntegrationMapping
from app.modules.integration.domain.enums import FieldType, MappingTransformation

logger = get_logger(__name__)


class MappingService:
    """Application service for mapping management."""

    def __init__(
        self,
        mapping_repository: Any,
        integration_repository: Any,
        schema_service: Any,
        validation_service: Any,
        event_publisher: Any,
    ):
        """Initialize mapping service.

        Args:
            mapping_repository: Repository for mapping persistence
            integration_repository: Repository for integrations
            schema_service: Service for schema inspection
            validation_service: Service for mapping validation
            event_publisher: Event publisher for domain events
        """
        self._mapping_repository = mapping_repository
        self._integration_repository = integration_repository
        self._schema_service = schema_service
        self._validation_service = validation_service
        self._event_publisher = event_publisher

    async def create_mapping(
        self,
        integration_id: UUID,
        name: str,
        source_entity: str,
        target_entity: str,
        field_mappings: list[dict[str, Any]],
        created_by: UUID,
        description: str | None = None,
        filters: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
    ) -> MappingConfigDTO:
        """Create a new data mapping.

        Args:
            integration_id: Integration ID
            name: Mapping name
            source_entity: Source entity name
            target_entity: Target entity name
            field_mappings: Field mapping configurations
            created_by: User creating mapping
            description: Optional description
            filters: Optional data filters
            options: Optional mapping options

        Returns:
            MappingConfigDTO: Created mapping

        Raises:
            NotFoundError: If integration not found
            ValidationError: If mapping configuration invalid
        """
        logger.info(
            "Creating mapping",
            integration_id=integration_id,
            name=name,
            source_entity=source_entity,
            target_entity=target_entity,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        # Validate field mappings
        await self._validate_field_mappings(integration, field_mappings)

        # Create mapping
        mapping = IntegrationMapping(
            integration_id=integration.id,
            name=name,
            source_entity=source_entity,
            target_entity=target_entity,
            field_mappings=field_mappings,
            description=description,
            filters=filters or {},
            options=options or {},
            created_by=created_by,
        )

        # Save mapping
        await self._mapping_repository.save(mapping)

        # Add to integration
        integration.add_mapping(mapping.id)
        await self._integration_repository.save(integration)

        # Publish events
        for event in mapping.collect_events():
            await self._event_publisher.publish(event)

        logger.info(
            "Mapping created successfully",
            mapping_id=mapping.id,
            integration_id=integration.id,
        )

        return MappingConfigDTO.from_domain(mapping)

    async def validate_mapping(
        self,
        integration_id: UUID,
        field_mappings: list[dict[str, Any]],
        source_entity: str,
        target_entity: str,
        test_data: list[dict[str, Any]] | None = None,
    ) -> MappingValidationResultDTO:
        """Validate mapping configuration.

        Args:
            integration_id: Integration ID
            field_mappings: Field mappings to validate
            source_entity: Source entity name
            target_entity: Target entity name
            test_data: Optional test data for validation

        Returns:
            MappingValidationResultDTO: Validation results

        Raises:
            NotFoundError: If integration not found
        """
        logger.info(
            "Validating mapping",
            integration_id=integration_id,
            source_entity=source_entity,
            target_entity=target_entity,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        start_time = datetime.utcnow()
        errors = []
        warnings = []
        tested_records = 0
        successful_mappings = 0
        failed_mappings = 0

        try:
            # Validate field mapping structure
            structural_errors = await self._validate_mapping_structure(field_mappings)
            errors.extend(structural_errors)

            # Get schemas for validation
            source_schema = await self._schema_service.get_entity_schema(
                integration=integration, entity=source_entity
            )

            target_schema = await self._schema_service.get_entity_schema(
                integration=integration, entity=target_entity, is_internal=True
            )

            # Validate field compatibility
            (
                compatibility_errors,
                compatibility_warnings,
            ) = await self._validate_field_compatibility(
                field_mappings, source_schema, target_schema
            )
            errors.extend(compatibility_errors)
            warnings.extend(compatibility_warnings)

            # Test with sample data if provided
            if test_data:
                test_results = await self._test_mapping_with_data(
                    field_mappings, test_data
                )
                tested_records = len(test_data)
                successful_mappings = test_results["successful"]
                failed_mappings = test_results["failed"]
                errors.extend(test_results["errors"])
                warnings.extend(test_results["warnings"])

        except Exception as e:
            logger.exception(
                "Mapping validation failed", integration_id=integration_id, error=str(e)
            )
            errors.append(
                {
                    "field": "validation",
                    "error": f"Validation process failed: {e!s}",
                    "severity": "error",
                }
            )

        # Calculate validation time
        validation_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        is_valid = len(errors) == 0

        logger.info(
            "Mapping validation completed",
            integration_id=integration_id,
            is_valid=is_valid,
            errors=len(errors),
            warnings=len(warnings),
        )

        return MappingValidationResultDTO(
            mapping_id=UUID(
                "00000000-0000-0000-0000-000000000000"
            ),  # No mapping ID for validation
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            tested_records=tested_records,
            successful_mappings=successful_mappings,
            failed_mappings=failed_mappings,
            validation_time_ms=validation_time,
        )

    async def auto_generate_mapping(
        self, integration_id: UUID, source_entity: str, target_entity: str
    ) -> list[dict[str, Any]]:
        """Auto-generate field mappings based on schema analysis.

        Args:
            integration_id: Integration ID
            source_entity: Source entity name
            target_entity: Target entity name

        Returns:
            list[dict[str, Any]]: Generated field mappings

        Raises:
            NotFoundError: If integration not found
        """
        logger.info(
            "Auto-generating mapping",
            integration_id=integration_id,
            source_entity=source_entity,
            target_entity=target_entity,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        # Get schemas
        source_schema = await self._schema_service.get_entity_schema(
            integration=integration, entity=source_entity
        )

        target_schema = await self._schema_service.get_entity_schema(
            integration=integration, entity=target_entity, is_internal=True
        )

        # Generate mappings
        field_mappings = []

        for source_field in source_schema.get("fields", []):
            # Find best match in target schema
            target_field = self._find_best_field_match(
                source_field, target_schema.get("fields", [])
            )

            if target_field:
                mapping = {
                    "source_field": source_field["name"],
                    "target_field": target_field["name"],
                    "field_type": target_field["type"],
                    "transformation": self._suggest_transformation(
                        source_field, target_field
                    ),
                    "transformation_config": {},
                    "is_required": target_field.get("required", False),
                    "default_value": target_field.get("default"),
                    "validation_rules": [],
                }
                field_mappings.append(mapping)

        logger.info(
            "Auto-generated mapping",
            integration_id=integration_id,
            field_count=len(field_mappings),
        )

        return field_mappings

    async def get_available_transformations(
        self, source_type: FieldType, target_type: FieldType
    ) -> list[dict[str, Any]]:
        """Get available transformations for field types.

        Args:
            source_type: Source field type
            target_type: Target field type

        Returns:
            list[dict[str, Any]]: Available transformations
        """
        transformations = []

        # Always available
        transformations.append(
            {
                "type": MappingTransformation.NONE.value,
                "name": "No transformation",
                "description": "Use value as-is",
            }
        )

        # String transformations
        if source_type == FieldType.STRING:
            transformations.extend(
                [
                    {
                        "type": MappingTransformation.UPPERCASE.value,
                        "name": "Uppercase",
                        "description": "Convert to uppercase",
                    },
                    {
                        "type": MappingTransformation.LOWERCASE.value,
                        "name": "Lowercase",
                        "description": "Convert to lowercase",
                    },
                    {
                        "type": MappingTransformation.TRIM.value,
                        "name": "Trim whitespace",
                        "description": "Remove leading/trailing whitespace",
                    },
                ]
            )

        # Date transformations
        if source_type.is_temporal or target_type.is_temporal:
            transformations.append(
                {
                    "type": MappingTransformation.DATE_FORMAT.value,
                    "name": "Date format",
                    "description": "Convert date format",
                    "config_schema": {
                        "input_format": {"type": "string", "required": True},
                        "output_format": {"type": "string", "required": True},
                    },
                }
            )

        # Number transformations
        if source_type.is_numeric or target_type.is_numeric:
            transformations.append(
                {
                    "type": MappingTransformation.NUMBER_FORMAT.value,
                    "name": "Number format",
                    "description": "Format number (decimals, currency, etc)",
                    "config_schema": {
                        "decimals": {"type": "integer", "default": 2},
                        "currency": {"type": "string", "optional": True},
                    },
                }
            )

        # Custom transformation always available
        transformations.append(
            {
                "type": MappingTransformation.CUSTOM.value,
                "name": "Custom transformation",
                "description": "Custom JavaScript transformation function",
                "config_schema": {"function": {"type": "string", "required": True}},
            }
        )

        return transformations

    async def _validate_field_mappings(
        self, integration: Any, field_mappings: list[dict[str, Any]]
    ) -> None:
        """Validate field mappings structure.

        Args:
            integration: Integration
            field_mappings: Field mappings to validate

        Raises:
            ValidationError: If mappings invalid
        """
        if not field_mappings:
            raise ValidationError("At least one field mapping is required")

        for idx, mapping in enumerate(field_mappings):
            # Required fields
            required_fields = [
                "source_field",
                "target_field",
                "field_type",
                "transformation",
            ]
            for field in required_fields:
                if field not in mapping:
                    raise ValidationError(
                        f"Field mapping {idx} missing required field: {field}"
                    )

            # Validate field type
            try:
                FieldType(mapping["field_type"])
            except ValueError:
                raise ValidationError(
                    f"Invalid field_type in mapping {idx}: {mapping['field_type']}"
                )

            # Validate transformation
            try:
                MappingTransformation(mapping["transformation"])
            except ValueError:
                raise ValidationError(
                    f"Invalid transformation in mapping {idx}: {mapping['transformation']}"
                )

    async def _validate_mapping_structure(
        self, field_mappings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Validate mapping structure.

        Args:
            field_mappings: Field mappings to validate

        Returns:
            list[dict[str, Any]]: Structure errors
        """
        errors = []

        if not field_mappings:
            errors.append(
                {
                    "field": "field_mappings",
                    "error": "At least one field mapping is required",
                    "severity": "error",
                }
            )
            return errors

        source_fields = set()
        target_fields = set()

        for idx, mapping in enumerate(field_mappings):
            # Check for duplicate source fields
            source_field = mapping.get("source_field")
            if source_field in source_fields:
                errors.append(
                    {
                        "field": f"field_mappings[{idx}].source_field",
                        "error": f"Duplicate source field: {source_field}",
                        "severity": "error",
                    }
                )
            source_fields.add(source_field)

            # Check for duplicate target fields
            target_field = mapping.get("target_field")
            if target_field in target_fields:
                errors.append(
                    {
                        "field": f"field_mappings[{idx}].target_field",
                        "error": f"Duplicate target field: {target_field}",
                        "severity": "error",
                    }
                )
            target_fields.add(target_field)

        return errors

    async def _validate_field_compatibility(
        self,
        field_mappings: list[dict[str, Any]],
        source_schema: dict[str, Any],
        target_schema: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Validate field compatibility.

        Args:
            field_mappings: Field mappings
            source_schema: Source schema
            target_schema: Target schema

        Returns:
            tuple: (errors, warnings)
        """
        errors = []
        warnings = []

        source_fields = {f["name"]: f for f in source_schema.get("fields", [])}
        target_fields = {f["name"]: f for f in target_schema.get("fields", [])}

        for idx, mapping in enumerate(field_mappings):
            source_field_name = mapping.get("source_field")
            target_field_name = mapping.get("target_field")

            # Check if source field exists
            if source_field_name not in source_fields:
                errors.append(
                    {
                        "field": f"field_mappings[{idx}].source_field",
                        "error": f"Source field not found: {source_field_name}",
                        "severity": "error",
                    }
                )
                continue

            # Check if target field exists
            if target_field_name not in target_fields:
                errors.append(
                    {
                        "field": f"field_mappings[{idx}].target_field",
                        "error": f"Target field not found: {target_field_name}",
                        "severity": "error",
                    }
                )
                continue

            # Check type compatibility
            source_field = source_fields[source_field_name]
            target_field = target_fields[target_field_name]

            if not self._are_types_compatible(
                source_field["type"], target_field["type"]
            ):
                warnings.append(
                    {
                        "field": f"field_mappings[{idx}]",
                        "error": f'Type mismatch: {source_field["type"]} -> {target_field["type"]}',
                        "severity": "warning",
                    }
                )

        return errors, warnings

    def _are_types_compatible(self, source_type: str, target_type: str) -> bool:
        """Check if field types are compatible.

        Args:
            source_type: Source field type
            target_type: Target field type

        Returns:
            bool: True if compatible
        """
        # Direct match
        if source_type == target_type:
            return True

        # String is compatible with most types
        if source_type == "string":
            return True

        # Numeric types are compatible
        numeric_types = {"integer", "float", "number"}
        if source_type in numeric_types and target_type in numeric_types:
            return True

        # Date types are compatible
        date_types = {"date", "datetime", "timestamp"}
        return bool(source_type in date_types and target_type in date_types)

    def _find_best_field_match(
        self, source_field: dict[str, Any], target_fields: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Find best matching target field for source field.

        Args:
            source_field: Source field definition
            target_fields: Available target fields

        Returns:
            dict[str, Any] | None: Best matching target field
        """
        source_name = source_field["name"].lower()
        source_type = source_field["type"]

        # Exact name match
        for field in target_fields:
            if field["name"].lower() == source_name:
                return field

        # Partial name match with type compatibility
        best_match = None
        best_score = 0

        for field in target_fields:
            target_name = field["name"].lower()
            target_type = field["type"]

            # Calculate name similarity
            name_score = self._calculate_name_similarity(source_name, target_name)

            # Type compatibility bonus
            type_score = (
                1.0 if self._are_types_compatible(source_type, target_type) else 0.5
            )

            # Combined score
            score = name_score * type_score

            if score > best_score and score > 0.3:  # Minimum threshold
                best_score = score
                best_match = field

        return best_match

    def _calculate_name_similarity(self, name1: str, name2: str) -> float:
        """Calculate similarity between field names.

        Args:
            name1: First field name
            name2: Second field name

        Returns:
            float: Similarity score (0-1)
        """
        # Simple similarity based on common substrings
        if name1 in name2 or name2 in name1:
            return 0.8

        # Check for common prefixes/suffixes
        if name1.startswith(name2[:3]) or name2.startswith(name1[:3]):
            return 0.6

        if name1.endswith(name2[-3:]) or name2.endswith(name1[-3:]):
            return 0.6

        # Check for common words
        words1 = set(name1.replace("_", " ").split())
        words2 = set(name2.replace("_", " ").split())

        if words1 & words2:
            return 0.4

        return 0.0

    def _suggest_transformation(
        self, source_field: dict[str, Any], target_field: dict[str, Any]
    ) -> str:
        """Suggest transformation for field mapping.

        Args:
            source_field: Source field definition
            target_field: Target field definition

        Returns:
            str: Suggested transformation
        """
        source_type = source_field["type"]
        target_type = target_field["type"]

        # No transformation if types match
        if source_type == target_type:
            return MappingTransformation.NONE.value

        # Date format transformation
        if source_type in ["date", "datetime"] and target_type in ["date", "datetime"]:
            return MappingTransformation.DATE_FORMAT.value

        # Number format transformation
        if source_type in ["integer", "float"] and target_type in ["integer", "float"]:
            return MappingTransformation.NUMBER_FORMAT.value

        # String transformations
        if target_type == "string":
            return MappingTransformation.NONE.value

        # Default to no transformation
        return MappingTransformation.NONE.value

    async def _test_mapping_with_data(
        self, field_mappings: list[dict[str, Any]], test_data: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Test mapping with sample data.

        Args:
            field_mappings: Field mappings
            test_data: Test data

        Returns:
            dict[str, Any]: Test results
        """
        results = {"successful": 0, "failed": 0, "errors": [], "warnings": []}

        for idx, record in enumerate(test_data):
            try:
                # Test each field mapping
                for mapping in field_mappings:
                    source_field = mapping["source_field"]

                    if source_field not in record:
                        if mapping.get("is_required", False):
                            results["errors"].append(
                                {
                                    "record": idx,
                                    "field": source_field,
                                    "error": "Required field missing from test data",
                                    "severity": "error",
                                }
                            )
                        continue

                    # Test transformation
                    try:
                        value = record[source_field]
                        self._apply_test_transformation(value, mapping)
                        # Transformation successful
                    except Exception as e:
                        results["errors"].append(
                            {
                                "record": idx,
                                "field": source_field,
                                "error": f"Transformation failed: {e!s}",
                                "severity": "error",
                            }
                        )

                results["successful"] += 1

            except Exception as e:
                results["failed"] += 1
                results["errors"].append(
                    {"record": idx, "error": str(e), "severity": "error"}
                )

        return results

    def _apply_test_transformation(self, value: Any, mapping: dict[str, Any]) -> Any:
        """Apply transformation for testing.

        Args:
            value: Input value
            mapping: Field mapping

        Returns:
            Any: Transformed value
        """
        transformation = MappingTransformation(mapping["transformation"])

        if transformation == MappingTransformation.NONE:
            return value

        if transformation == MappingTransformation.UPPERCASE:
            return str(value).upper()

        if transformation == MappingTransformation.LOWERCASE:
            return str(value).lower()

        if transformation == MappingTransformation.TRIM:
            return str(value).strip()

        # For other transformations, just return the value
        # In a real implementation, this would apply the actual transformation
        return value
