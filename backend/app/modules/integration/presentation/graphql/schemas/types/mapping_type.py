"""GraphQL types for Mapping entities.

This module provides GraphQL type definitions for data mapping,
including field mappings, transformations, and validation.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import FieldTypeEnum, MappingTransformationEnum, SyncDirectionEnum


@strawberry.type
class FieldValidationRule:
    """GraphQL type for field validation rules."""

    rule_name: str
    rule_type: str  # "required", "format", "range", "custom"
    parameters: dict[str, Any] = strawberry.field(default_factory=dict)
    error_message: str = "Validation failed"
    is_enabled: bool = True


@strawberry.type
class FieldTransformation:
    """GraphQL type for field transformations."""

    transformation_type: MappingTransformationEnum
    parameters: dict[str, Any] = strawberry.field(default_factory=dict)

    # Custom transformation details
    custom_function: str | None = None
    custom_script: str | None = None

    # Transformation order
    order: int = 0
    is_enabled: bool = True


@strawberry.type
class FieldMapping:
    """GraphQL type for individual field mappings."""

    mapping_id: UUID
    source_field: str
    target_field: str

    # Field types
    source_type: FieldTypeEnum
    target_type: FieldTypeEnum

    # Mapping configuration
    is_required: bool = False
    default_value: Any | None = None

    # Transformations
    transformations: list[FieldTransformation] = strawberry.field(default_factory=list)

    # Validation
    validation_rules: list[FieldValidationRule] = strawberry.field(default_factory=list)

    # Mapping metadata
    description: str | None = None
    examples: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Status
    is_active: bool = True
    last_validated: datetime | None = None
    validation_status: str = "valid"  # "valid", "warning", "error"
    validation_message: str | None = None


@strawberry.type
class MappingValidationResult:
    """GraphQL type for mapping validation results."""

    is_valid: bool
    validation_passed: bool

    # Overall results
    total_fields: int
    valid_fields: int
    invalid_fields: int
    warning_fields: int

    # Field-level results
    field_results: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Issues
    errors: list[str] = strawberry.field(default_factory=list)
    warnings: list[str] = strawberry.field(default_factory=list)
    suggestions: list[str] = strawberry.field(default_factory=list)

    # Sample data validation
    sample_data_valid: bool = True
    sample_validation_errors: list[str] = strawberry.field(default_factory=list)

    # Performance analysis
    estimated_processing_time: float = 0.0
    complexity_score: int = 1  # 1-10 scale

    # Timestamps
    validated_at: datetime


@strawberry.type
class MappingSchema:
    """GraphQL type for mapping schemas."""

    schema_id: UUID
    name: str
    version: str

    # Schema definition
    source_schema: dict[str, Any] = strawberry.field(default_factory=dict)
    target_schema: dict[str, Any] = strawberry.field(default_factory=dict)

    # Schema metadata
    description: str | None = None
    documentation_url: str | None = None

    # Compatibility
    is_backward_compatible: bool = True
    breaking_changes: list[str] = strawberry.field(default_factory=list)

    # Timestamps
    created_at: datetime
    updated_at: datetime


@strawberry.type
class MappingTemplate:
    """GraphQL type for mapping templates."""

    template_id: UUID
    name: str
    description: str | None = None

    # Template configuration
    source_system: str
    target_system: str
    category: str

    # Template mapping
    field_mappings: list[FieldMapping] = strawberry.field(default_factory=list)

    # Usage statistics
    usage_count: int = 0
    success_rate: float = 100.0

    # Template metadata
    tags: list[str] = strawberry.field(default_factory=list)
    is_public: bool = False
    created_by: UUID

    # Timestamps
    created_at: datetime
    updated_at: datetime


@strawberry.type
class MappingConfiguration:
    """GraphQL type for mapping configuration."""

    # Sync configuration
    sync_direction: SyncDirectionEnum
    batch_size: int = 100
    parallel_processing: bool = False
    max_parallel_jobs: int = 1

    # Error handling
    continue_on_error: bool = True
    max_errors: int = 10
    error_threshold_percentage: float = 5.0

    # Performance
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    enable_compression: bool = False

    # Monitoring
    enable_metrics: bool = True
    enable_logging: bool = True
    log_level: str = "INFO"

    # Notifications
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notification_channels: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class MappingType:
    """GraphQL type for data mapping configuration."""

    mapping_id: UUID
    integration_id: UUID
    name: str
    description: str | None = None

    # Mapping configuration
    configuration: MappingConfiguration

    # Field mappings
    field_mappings: list[FieldMapping] = strawberry.field(default_factory=list)

    # Schema information
    source_schema: MappingSchema | None = None
    target_schema: MappingSchema | None = None

    # Status
    is_active: bool = True
    is_validated: bool = False

    # Validation results
    last_validation: MappingValidationResult | None = None

    # Usage statistics
    total_records_processed: int = 0
    successful_mappings: int = 0
    failed_mappings: int = 0

    # Performance metrics
    average_processing_time_ms: float = 0.0
    throughput_records_per_second: float = 0.0

    # Template information
    based_on_template: UUID | None = None
    template_version: str | None = None

    # Timestamps
    created_at: datetime
    updated_at: datetime
    last_used: datetime | None = None

    @strawberry.field
    def success_rate(self) -> float:
        """Calculate mapping success rate."""
        if self.total_records_processed == 0:
            return 0.0

        return (self.successful_mappings / self.total_records_processed) * 100

    @strawberry.field
    def error_rate(self) -> float:
        """Calculate mapping error rate."""
        if self.total_records_processed == 0:
            return 0.0

        return (self.failed_mappings / self.total_records_processed) * 100

    @strawberry.field
    def complexity_score(self) -> int:
        """Calculate mapping complexity score (1-10)."""
        score = 1

        # Add complexity based on number of fields
        field_count = len(self.field_mappings)
        if field_count > 50:
            score += 3
        elif field_count > 20:
            score += 2
        elif field_count > 10:
            score += 1

        # Add complexity based on transformations
        total_transformations = sum(
            len(mapping.transformations) for mapping in self.field_mappings
        )
        if total_transformations > 20:
            score += 2
        elif total_transformations > 10:
            score += 1

        # Add complexity for custom transformations
        custom_transformations = sum(
            1
            for mapping in self.field_mappings
            for transformation in mapping.transformations
            if transformation.transformation_type == MappingTransformationEnum.CUSTOM
        )
        score += min(custom_transformations, 3)

        return min(score, 10)


@strawberry.type
class MappingPreview:
    """GraphQL type for mapping preview results."""

    sample_input: dict[str, Any] = strawberry.field(default_factory=dict)
    sample_output: dict[str, Any] = strawberry.field(default_factory=dict)

    # Transformation details
    applied_transformations: list[str] = strawberry.field(default_factory=list)
    transformation_log: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Validation results
    validation_passed: bool = True
    validation_errors: list[str] = strawberry.field(default_factory=list)
    validation_warnings: list[str] = strawberry.field(default_factory=list)

    # Performance
    processing_time_ms: int = 0

    # Generated at
    generated_at: datetime


@strawberry.type
class MappingError:
    """GraphQL type for mapping-specific errors."""

    success: bool = False
    message: str
    error_code: str

    # Mapping-specific details
    mapping_id: UUID | None = None
    field_name: str | None = None
    transformation_step: str | None = None

    # Error details
    source_value: Any | None = None
    expected_type: str | None = None
    actual_type: str | None = None

    # Validation details
    validation_rule: str | None = None
    rule_parameters: dict[str, Any] = strawberry.field(default_factory=dict)

    # Recovery suggestions
    recovery_suggestions: list[str] = strawberry.field(default_factory=list)
    can_auto_fix: bool = False
    suggested_fix: str | None = None

    # Context
    record_index: int | None = None
    batch_id: UUID | None = None

    # Timestamps
    occurred_at: datetime


@strawberry.type
class MappingAnalytics:
    """GraphQL type for mapping analytics."""

    mapping_id: UUID
    period_start: datetime
    period_end: datetime

    # Usage analytics
    total_executions: int = 0
    total_records: int = 0
    success_rate: float = 0.0
    error_rate: float = 0.0

    # Performance analytics
    average_processing_time: float = 0.0
    throughput_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)
    performance_bottlenecks: list[str] = strawberry.field(default_factory=list)

    # Error analytics
    common_errors: list[dict[str, Any]] = strawberry.field(default_factory=list)
    error_trends: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Field analytics
    field_success_rates: dict[str, float] = strawberry.field(default_factory=dict)
    problematic_fields: list[str] = strawberry.field(default_factory=list)

    # Optimization suggestions
    optimization_suggestions: list[str] = strawberry.field(default_factory=list)
    estimated_improvement: dict[str, float] = strawberry.field(default_factory=dict)


__all__ = [
    "FieldMapping",
    "FieldTransformation",
    "FieldValidationRule",
    "MappingAnalytics",
    "MappingConfiguration",
    "MappingError",
    "MappingPreview",
    "MappingSchema",
    "MappingTemplate",
    "MappingType",
    "MappingValidationResult",
]
