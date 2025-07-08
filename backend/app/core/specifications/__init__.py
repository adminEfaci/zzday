"""Specification Pattern Implementation

Provides comprehensive specification pattern with SQL mapping support.
"""

from app.core.domain.specification import (  # Concrete implementations; Utility specifications; Base classes; Utilities
    AndSpecification,
    CollectionSpecification,
    CompositeSpecification,
    FalseSpecification,
    LambdaSpecification,
    NotSpecification,
    OrSpecification,
    Specification,
    SpecificationValidator,
    TrueSpecification,
    all_satisfy,
    any_satisfy,
    create_lambda_spec,
)
from app.core.infrastructure.specification import (  # Field specifications; SQL mapping; Errors; Factory functions
    ComparisonOperator,
    DateRangeSpecification,
    FieldSpecification,
    InvalidFieldSpecificationError,
    QueryOptimizationError,
    QueryOptimizationHint,
    SpecificationEvaluator,
    SpecificationMapper,
    SpecificationMappingError,
    UnregisteredSpecificationError,
    create_specification_evaluator,
    date_range,
    field_contains,
    field_equals,
    field_in,
    field_not_null,
)

__all__ = [
    # Concrete implementations
    "AndSpecification",
    "CollectionSpecification",
    # Field specifications
    "ComparisonOperator",
    "CompositeSpecification",
    "DateRangeSpecification",
    "FalseSpecification",
    "FieldSpecification",
    "InvalidFieldSpecificationError",
    # Utility specifications
    "LambdaSpecification",
    "NotSpecification",
    "OrSpecification",
    "QueryOptimizationError",
    "QueryOptimizationHint",
    # Base classes
    "Specification",
    "SpecificationEvaluator",
    # SQL mapping
    "SpecificationMapper",
    # Errors
    "SpecificationMappingError",
    # Utilities
    "SpecificationValidator",
    "TrueSpecification",
    "UnregisteredSpecificationError",
    "all_satisfy",
    "any_satisfy",
    "create_lambda_spec",
    # Factory functions
    "create_specification_evaluator",
    "date_range",
    "field_contains",
    "field_equals",
    "field_in",
    "field_not_null",
]
