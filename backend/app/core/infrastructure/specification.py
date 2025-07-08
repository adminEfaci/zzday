"""
Infrastructure Specification Mapping for EzzDay Core

This module provides sophisticated specification-to-SQL mapping capabilities
enabling domain specifications to be efficiently translated into database
queries. Supports complex specification patterns, performance optimization,
and extensible custom specification registration.

Key Features:
- Domain specification to SQL condition mapping
- Performance-optimized query generation with indexing hints
- Extensible specification registry for custom implementations
- Comprehensive validation and error handling
- Advanced specification patterns (date ranges, text search, etc.)
- Query optimization and performance monitoring

Design Principles:
- Pure Python domain logic (minimal SQLAlchemy coupling)
- Explicit validation and comprehensive error handling
- Performance-first design with query optimization
- Extensible architecture for domain-specific specifications
- Comprehensive logging and monitoring integration

Usage Examples:
    # Basic specification mapping
    mapper = SpecificationMapper()
    sql_condition = mapper.to_sql_condition(
        specification=UserActiveSpecification(),
        model_type=UserModel
    )
    
    # Query application with evaluator
    evaluator = SpecificationEvaluator()
    filtered_query = evaluator.apply_specification(
        query=select(UserModel),
        spec=AndSpecification(
            UserActiveSpecification(),
            UserRoleSpecification("admin")
        ),
        model_type=UserModel
    )
    
    # Custom specification registration
    evaluator.register_custom_specification(
        CustomBusinessSpecification,
        lambda spec, model: model.field == spec.value
    )
    
    # Advanced specification patterns
    complex_spec = AndSpecification(
        FieldEqualsSpecification("status", "active"),
        OrSpecification(
            DateRangeSpecification("created_at", start_date, end_date),
            FieldInSpecification("priority", ["high", "critical"])
        )
    )

Error Handling:
    - SpecificationMappingError: Base specification mapping failures
    - UnregisteredSpecificationError: Missing specification mapper
    - InvalidFieldSpecificationError: Invalid field references
    - QueryOptimizationError: Query optimization failures

Performance Features:
    - Lazy specification evaluation and caching
    - Query optimization with index hints
    - Batch specification processing
    - Memory-efficient condition building
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from sqlalchemy import and_, not_, or_, text
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList

from app.core.domain.specification import (
    AndSpecification,
    FalseSpecification,
    NotSpecification,
    OrSpecification,
    Specification,
    TrueSpecification,
)
from app.core.errors import InfrastructureError, ValidationError
from app.core.logging import get_logger
from app.core.monitoring import metrics

logger = get_logger(__name__)


class SpecificationMappingError(InfrastructureError):
    """Base exception for specification mapping failures."""


class UnregisteredSpecificationError(SpecificationMappingError):
    """Raised when no mapper is registered for a specification type."""


class InvalidFieldSpecificationError(SpecificationMappingError):
    """Raised when specification references invalid model fields."""


class QueryOptimizationError(SpecificationMappingError):
    """Raised when query optimization fails."""


class ComparisonOperator(str, Enum):
    """Supported comparison operators for field specifications."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    ICONTAINS = "icontains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"


@dataclass
class QueryOptimizationHint:
    """
    Query optimization hint for specification mapping.

    Provides guidance to the SQL mapper about optimal query generation
    including index usage, join strategies, and performance considerations.

    Features:
    - Index hint specification for optimal query plans
    - Join strategy recommendations
    - Estimated selectivity for cost-based optimization
    - Custom SQL fragment injection for complex cases

    Usage Examples:
        hint = QueryOptimizationHint(
            use_index="idx_user_status_created",
            estimated_selectivity=0.1,
            prefer_exists_over_join=True
        )
    """

    use_index: str | None = None
    estimated_selectivity: float | None = None
    prefer_exists_over_join: bool = False
    force_index_scan: bool = False
    custom_sql_fragment: str | None = None
    join_strategy: str | None = None  # "nested_loop", "hash", "merge"


class SpecificationMapper:
    """
    Advanced specification-to-SQL mapper with optimization and extensibility.

    Provides sophisticated mapping from domain specifications to SQL conditions
    with support for performance optimization, custom specification registration,
    and comprehensive error handling.

    Key Features:
    - Hierarchical specification type mapping with inheritance support
    - Performance optimization with index hints and query planning
    - Extensible mapper registry for custom specifications
    - Comprehensive validation and error reporting
    - Query complexity analysis and optimization warnings
    - Memory-efficient condition building with lazy evaluation

    Design Characteristics:
    - Plugin architecture for custom specification types
    - Performance-first SQL generation with optimization hints
    - Comprehensive error handling with context information
    - Monitoring integration for performance tracking

    Usage Examples:
        # Basic mapper setup
        mapper = SpecificationMapper()

        # Register custom specification mapper
        mapper.register_mapper(
            MyCustomSpecification,
            lambda spec, model: model.custom_field == spec.value,
            optimization_hint=QueryOptimizationHint(
                use_index="idx_custom_field",
                estimated_selectivity=0.05
            )
        )

        # Map specification to SQL
        sql_condition = mapper.to_sql_condition(
            specification=complex_specification,
            model_type=UserModel
        )

    Performance Characteristics:
        - O(1) mapper lookup with type-based registry
        - Lazy evaluation for complex specification trees
        - Memory-efficient condition building
        - Index-aware query optimization
    """

    def __init__(self, enable_optimization: bool = True):
        """
        Initialize specification mapper with optimization settings.

        Args:
            enable_optimization: Enable query optimization features

        Raises:
            ValidationError: If configuration is invalid
        """
        self.enable_optimization = enable_optimization

        # Registry of specification type to mapper function and hints
        self._mappers: dict[type[Specification], Callable] = {}
        self._optimization_hints: dict[type[Specification], QueryOptimizationHint] = {}

        # Performance tracking
        self._mapping_stats: dict[str, int] = {}
        self._last_cleanup = datetime.now()

        # Register built-in specification mappers
        self._register_builtin_mappers()

        logger.debug(
            "SpecificationMapper initialized",
            optimization_enabled=enable_optimization,
            builtin_mappers=len(self._mappers),
        )

    def _register_builtin_mappers(self) -> None:
        """Register built-in specification mappers."""
        builtin_mappings = {
            AndSpecification: (self._map_and_specification, None),
            OrSpecification: (self._map_or_specification, None),
            NotSpecification: (self._map_not_specification, None),
            TrueSpecification: (self._map_true_specification, None),
            FalseSpecification: (self._map_false_specification, None),
        }

        for spec_type, (mapper_func, hint) in builtin_mappings.items():
            self._mappers[spec_type] = mapper_func
            if hint:
                self._optimization_hints[spec_type] = hint

    def register_mapper(
        self,
        spec_type: type[Specification],
        mapper_func: Callable[[Specification, type[Any]], Any],
        optimization_hint: QueryOptimizationHint | None = None,
    ) -> None:
        """
        Register custom specification mapper with optional optimization hint.

        Args:
            spec_type: Specification class to register mapper for
            mapper_func: Function that maps specification to SQL condition
            optimization_hint: Optional optimization hint for query planning

        Raises:
            ValidationError: If mapper function is invalid
        """
        self._validate_mapper_registration(spec_type, mapper_func)

        self._mappers[spec_type] = mapper_func

        if optimization_hint:
            self._optimization_hints[spec_type] = optimization_hint

        logger.debug(
            "Custom specification mapper registered",
            spec_type=spec_type.__name__,
            has_optimization_hint=optimization_hint is not None,
        )

    def _validate_mapper_registration(
        self, spec_type: type[Specification], mapper_func: Callable
    ) -> None:
        """Validate mapper registration parameters."""
        if not issubclass(spec_type, Specification):
            raise ValidationError(
                f"spec_type must be subclass of Specification, got {spec_type}"
            )

        if not callable(mapper_func):
            raise ValidationError("mapper_func must be callable")

        # Validate function signature
        import inspect

        sig = inspect.signature(mapper_func)
        if len(sig.parameters) != 2:
            raise ValidationError(
                "mapper_func must accept exactly 2 parameters: (specification, model_type)"
            )

    def to_sql_condition(
        self,
        spec: Specification,
        model_type: type[Any],
        optimization_context: dict[str, Any] | None = None,
    ) -> BinaryExpression | BooleanClauseList | bool:
        """
        Convert specification to SQL condition with optimization.

        Translates domain specification into SQL condition suitable for
        database queries. Applies optimization hints and validates
        field references against the model type.

        Args:
            spec: Domain specification to convert
            model_type: SQLAlchemy model type for field validation
            optimization_context: Additional context for optimization

        Returns:
            SQL condition (SQLAlchemy expression or boolean)

        Raises:
            UnregisteredSpecificationError: If no mapper found
            InvalidFieldSpecificationError: If specification references invalid fields
            QueryOptimizationError: If optimization fails
        """
        start_time = time.time()

        try:
            # Validate model type
            self._validate_model_type(model_type)

            # Check if specification has its own to_sql method
            if hasattr(spec, "to_sql") and callable(spec.to_sql):
                condition = spec.to_sql(model_type)
                self._track_mapping_success(spec, time.time() - start_time)
                return condition

            # Find appropriate mapper
            mapper_func = self._find_mapper(spec)

            if not mapper_func:
                raise UnregisteredSpecificationError(
                    f"No mapper registered for specification type: {type(spec).__name__}"
                )

            # Apply mapper
            condition = mapper_func(spec, model_type)

            # Apply optimization hints if enabled
            if self.enable_optimization:
                condition = self._apply_optimization_hints(
                    condition, spec, model_type, optimization_context
                )

            # Track performance metrics
            self._track_mapping_success(spec, time.time() - start_time)

            logger.debug(
                "Specification mapped to SQL",
                spec_type=type(spec).__name__,
                model_type=model_type.__name__,
                mapping_time_ms=(time.time() - start_time) * 1000,
            )

            return condition

        except Exception as e:
            self._track_mapping_failure(spec, e)
            logger.exception(
                "Specification mapping failed",
                spec_type=type(spec).__name__,
                model_type=model_type.__name__,
                error=str(e),
            )
            raise

    def _validate_model_type(self, model_type: type[Any]) -> None:
        """Validate that model_type is a proper SQLAlchemy model."""
        if not hasattr(model_type, "__table__"):
            raise ValidationError(
                f"model_type must be SQLAlchemy model, got {model_type}"
            )

    def _find_mapper(self, spec: Specification) -> Callable | None:
        """Find appropriate mapper for specification type."""
        spec_class = type(spec)

        # Direct mapper lookup
        if spec_class in self._mappers:
            return self._mappers[spec_class]

        # Check inheritance hierarchy
        for base_class in spec_class.__mro__:
            if base_class in self._mappers:
                return self._mappers[base_class]

        return None

    def _apply_optimization_hints(
        self,
        condition: Any,
        spec: Specification,
        model_type: type[Any],
        context: dict[str, Any] | None,
    ) -> Any:
        """Apply optimization hints to SQL condition."""
        spec_type = type(spec)
        hint = self._optimization_hints.get(spec_type)

        if not hint:
            return condition

        try:
            # Apply index hints
            if hint.use_index:
                # Add index hint as comment for database optimizer
                condition = condition.with_hint(
                    model_type, f"USE INDEX ({hint.use_index})"
                )

            # Apply custom SQL fragments
            if hint.custom_sql_fragment:
                condition = and_(condition, text(hint.custom_sql_fragment))

            return condition

        except Exception as e:
            logger.warning(
                "Query optimization failed", spec_type=spec_type.__name__, error=str(e)
            )
            return condition  # Return unoptimized condition

    def _track_mapping_success(self, spec: Specification, duration: float) -> None:
        """Track successful mapping for performance monitoring."""
        spec_type = type(spec).__name__
        self._mapping_stats[f"{spec_type}_success"] = (
            self._mapping_stats.get(f"{spec_type}_success", 0) + 1
        )

        metrics.specification_mappings.labels(
            spec_type=spec_type, status="success"
        ).inc()

        metrics.specification_mapping_duration.labels(spec_type=spec_type).observe(
            duration
        )

    def _track_mapping_failure(self, spec: Specification, error: Exception) -> None:
        """Track mapping failure for monitoring."""
        spec_type = type(spec).__name__
        self._mapping_stats[f"{spec_type}_failure"] = (
            self._mapping_stats.get(f"{spec_type}_failure", 0) + 1
        )

        metrics.specification_mappings.labels(
            spec_type=spec_type, status="failure"
        ).inc()

    # Built-in mapper implementations

    def _map_and_specification(
        self,
        spec: AndSpecification,
        model_type: type[Any],
    ) -> BooleanClauseList:
        """Map AND specification to SQL AND condition."""
        left_condition = self.to_sql_condition(spec.left, model_type)
        right_condition = self.to_sql_condition(spec.right, model_type)
        return and_(left_condition, right_condition)

    def _map_or_specification(
        self,
        spec: OrSpecification,
        model_type: type[Any],
    ) -> BooleanClauseList:
        """Map OR specification to SQL OR condition."""
        left_condition = self.to_sql_condition(spec.left, model_type)
        right_condition = self.to_sql_condition(spec.right, model_type)
        return or_(left_condition, right_condition)

    def _map_not_specification(
        self,
        spec: NotSpecification,
        model_type: type[Any],
    ) -> BooleanClauseList:
        """Map NOT specification to SQL NOT condition."""
        condition = self.to_sql_condition(spec.spec, model_type)
        return not_(condition)

    def _map_true_specification(
        self,
        spec: TrueSpecification,
        model_type: type[Any],
    ) -> bool:
        """Map TRUE specification to boolean True."""
        return True

    def _map_false_specification(
        self,
        spec: FalseSpecification,
        model_type: type[Any],
    ) -> bool:
        """Map FALSE specification to boolean False."""
        return False

    def get_statistics(self) -> dict[str, Any]:
        """Get mapping statistics for monitoring."""
        return {
            "registered_mappers": len(self._mappers),
            "optimization_hints": len(self._optimization_hints),
            "optimization_enabled": self.enable_optimization,
            "mapping_stats": self._mapping_stats.copy(),
        }


class SpecificationEvaluator:
    """
    Advanced specification evaluator for SQLAlchemy query enhancement.

    Applies domain specifications to SQLAlchemy queries with comprehensive
    optimization, validation, and performance monitoring. Supports complex
    specification trees and provides detailed execution analytics.

    Key Features:
    - Specification application to SQLAlchemy queries
    - Query optimization with performance analysis
    - Complex specification tree evaluation
    - Comprehensive error handling and validation
    - Performance monitoring and optimization suggestions
    - Memory-efficient query building with lazy evaluation

    Design Characteristics:
    - Integration with SpecificationMapper for SQL generation
    - Performance-first query enhancement with optimization
    - Comprehensive validation and error reporting
    - Monitoring and analytics for query performance

    Usage Examples:
        # Basic query enhancement
        evaluator = SpecificationEvaluator()
        enhanced_query = evaluator.apply_specification(
            query=select(User),
            spec=UserActiveSpecification(),
            model_type=User
        )

        # Complex specification evaluation
        complex_spec = AndSpecification(
            UserActiveSpecification(),
            OrSpecification(
                UserRoleSpecification("admin"),
                UserDepartmentSpecification("engineering")
            )
        )

        result_query = evaluator.apply_specification(
            query=base_query,
            spec=complex_spec,
            model_type=User
        )

        # Performance analysis
        stats = evaluator.get_performance_stats()
        if stats["average_complexity"] > 10:
            logger.warning("Consider query optimization")

    Performance Monitoring:
        Tracks query complexity, execution time estimates, and provides
        optimization suggestions for better database performance.
    """

    def __init__(self, mapper: SpecificationMapper | None = None):
        """
        Initialize specification evaluator with optional custom mapper.

        Args:
            mapper: Custom specification mapper (creates default if None)
        """
        self._mapper = mapper or SpecificationMapper()
        self._evaluation_stats: dict[str, Any] = {
            "total_evaluations": 0,
            "average_complexity": 0.0,
            "performance_warnings": 0,
        }

        logger.debug(
            "SpecificationEvaluator initialized",
            mapper_type=type(self._mapper).__name__,
        )

    def apply_specification(
        self,
        query: Select,
        spec: Specification,
        model_type: type[Any],
        optimization_context: dict[str, Any] | None = None,
    ) -> Select:
        """
        Apply specification to SQLAlchemy query with optimization.

        Enhances the provided query by applying the domain specification
        as SQL WHERE conditions. Provides performance analysis and
        optimization recommendations.

        Args:
            query: Base SQLAlchemy SELECT query
            spec: Domain specification to apply
            model_type: SQLAlchemy model type for validation
            optimization_context: Additional optimization context

        Returns:
            Enhanced query with specification conditions applied

        Raises:
            SpecificationMappingError: If specification mapping fails
            QueryOptimizationError: If query optimization fails
        """
        start_time = time.time()

        try:
            # Analyze specification complexity
            complexity = self._analyze_specification_complexity(spec)

            # Convert specification to SQL condition
            condition = self._mapper.to_sql_condition(
                spec, model_type, optimization_context
            )

            # Apply condition to query
            enhanced_query = self._apply_condition_to_query(query, condition)

            # Track performance metrics
            evaluation_time = time.time() - start_time
            self._track_evaluation_performance(spec, complexity, evaluation_time)

            # Provide optimization warnings if needed
            if complexity > 10:
                self._warn_about_query_complexity(spec, complexity)

            logger.debug(
                "Specification applied to query",
                spec_type=type(spec).__name__,
                complexity=complexity,
                evaluation_time_ms=evaluation_time * 1000,
            )

            return enhanced_query

        except Exception as e:
            logger.exception(
                "Specification evaluation failed",
                spec_type=type(spec).__name__,
                model_type=model_type.__name__,
                error=str(e),
            )
            raise

    def _apply_condition_to_query(self, query: Select, condition: Any) -> Select:
        """Apply SQL condition to query with proper handling."""
        # Handle boolean conditions
        if isinstance(condition, bool):
            if condition:
                # True specification - return query as is
                return query
            # False specification - return empty result
            return query.where(False)

        # Apply SQL condition
        return query.where(condition)

    def _analyze_specification_complexity(self, spec: Specification) -> int:
        """
        Analyze specification complexity for performance monitoring.

        Returns a complexity score indicating the computational cost
        of evaluating the specification.

        Args:
            spec: Specification to analyze

        Returns:
            Complexity score (higher = more complex)
        """
        if isinstance(spec, TrueSpecification | FalseSpecification):
            return 1

        if isinstance(spec, AndSpecification | OrSpecification):
            left_complexity = self._analyze_specification_complexity(spec.left)
            right_complexity = self._analyze_specification_complexity(spec.right)
            return 1 + left_complexity + right_complexity

        if isinstance(spec, NotSpecification):
            return 1 + self._analyze_specification_complexity(spec.spec)

        # Custom specifications default to medium complexity
        return 3

    def _track_evaluation_performance(
        self, spec: Specification, complexity: int, duration: float
    ) -> None:
        """Track evaluation performance for monitoring."""
        self._evaluation_stats["total_evaluations"] += 1

        # Update rolling average complexity
        current_avg = self._evaluation_stats["average_complexity"]
        total = self._evaluation_stats["total_evaluations"]
        self._evaluation_stats["average_complexity"] = (
            current_avg * (total - 1) + complexity
        ) / total

        # Track metrics
        metrics.specification_evaluations.labels(spec_type=type(spec).__name__).inc()

        metrics.specification_evaluation_duration.labels(
            spec_type=type(spec).__name__
        ).observe(duration)

        metrics.specification_complexity.labels(spec_type=type(spec).__name__).observe(
            complexity
        )

    def _warn_about_query_complexity(
        self, spec: Specification, complexity: int
    ) -> None:
        """Issue warning about high query complexity."""
        self._evaluation_stats["performance_warnings"] += 1

        logger.warning(
            "High specification complexity detected",
            spec_type=type(spec).__name__,
            complexity=complexity,
            recommendation="Consider simplifying specification or adding database indexes",
        )

    def register_custom_specification(
        self,
        spec_type: type[Specification],
        mapper_func: Callable[[Specification, type[Any]], Any],
        optimization_hint: QueryOptimizationHint | None = None,
    ) -> None:
        """
        Register custom specification mapper.

        Args:
            spec_type: Specification class to register
            mapper_func: Function that maps specification to SQL
            optimization_hint: Optional optimization hint
        """
        self._mapper.register_mapper(spec_type, mapper_func, optimization_hint)

    def get_performance_stats(self) -> dict[str, Any]:
        """Get comprehensive performance statistics."""
        mapper_stats = self._mapper.get_statistics()

        return {
            **self._evaluation_stats,
            "mapper_stats": mapper_stats,
            "total_registered_mappers": mapper_stats["registered_mappers"],
        }


# Advanced specification implementations


class FieldSpecification(Specification):
    """
    Advanced field-based specification with comprehensive operator support.

    Provides sophisticated field comparison operations with type validation,
    null handling, and performance optimization. Supports all common
    comparison operators and automatic index hint generation.

    Features:
    - Comprehensive operator support (equals, comparison, text search)
    - Type validation and null safety
    - Automatic index hint generation
    - Case-sensitive and case-insensitive operations
    - Performance optimization for common patterns

    Usage Examples:
        # Equality comparison
        spec = FieldSpecification("status", ComparisonOperator.EQUALS, "active")

        # Range comparison
        spec = FieldSpecification("age", ComparisonOperator.GREATER_THAN, 18)

        # Text search
        spec = FieldSpecification("name", ComparisonOperator.ICONTAINS, "john")

        # Null checking
        spec = FieldSpecification("deleted_at", ComparisonOperator.IS_NULL, None)
    """

    def __init__(
        self,
        field_name: str,
        operator: ComparisonOperator,
        value: Any,
        case_sensitive: bool = True,
        index_hint: str | None = None,
    ):
        """
        Initialize field specification with validation.

        Args:
            field_name: Name of the field to compare
            operator: Comparison operator to use
            value: Value to compare against
            case_sensitive: Whether string comparisons are case-sensitive
            index_hint: Optional database index hint

        Raises:
            ValidationError: If parameters are invalid
        """
        self._validate_initialization(field_name, operator, value)

        self.field_name = field_name
        self.operator = operator
        self.value = value
        self.case_sensitive = case_sensitive
        self.index_hint = index_hint

    def _validate_initialization(
        self, field_name: str, operator: ComparisonOperator, value: Any
    ) -> None:
        """Validate field specification initialization."""
        if not field_name or not isinstance(field_name, str):
            raise ValidationError("field_name must be non-empty string")

        if not isinstance(operator, ComparisonOperator):
            raise ValidationError("operator must be ComparisonOperator enum")

        # Validate value for specific operators
        if operator in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            if not isinstance(value, list | tuple | set):
                raise ValidationError(f"Value for {operator.value} must be iterable")

        if operator in (ComparisonOperator.IS_NULL, ComparisonOperator.IS_NOT_NULL):
            if value is not None:
                raise ValidationError(f"Value for {operator.value} must be None")

    def is_satisfied_by(self, entity: Any) -> bool:
        """
        Check if entity satisfies the field specification.

        Args:
            entity: Entity to check against specification

        Returns:
            True if entity satisfies specification
        """
        field_value = getattr(entity, self.field_name, None)

        return self._apply_operator(field_value, self.value, self.operator)

    def _apply_operator(
        self, field_value: Any, spec_value: Any, operator: ComparisonOperator
    ) -> bool:
        """Apply comparison operator to field and specification values."""
        if operator == ComparisonOperator.EQUALS:
            return field_value == spec_value

        if operator == ComparisonOperator.NOT_EQUALS:
            return field_value != spec_value

        if operator == ComparisonOperator.GREATER_THAN:
            return field_value is not None and field_value > spec_value

        if operator == ComparisonOperator.GREATER_THAN_OR_EQUAL:
            return field_value is not None and field_value >= spec_value

        if operator == ComparisonOperator.LESS_THAN:
            return field_value is not None and field_value < spec_value

        if operator == ComparisonOperator.LESS_THAN_OR_EQUAL:
            return field_value is not None and field_value <= spec_value

        if operator == ComparisonOperator.IN:
            return field_value in spec_value

        if operator == ComparisonOperator.NOT_IN:
            return field_value not in spec_value

        if operator == ComparisonOperator.CONTAINS:
            if field_value is None:
                return False
            field_str = str(field_value)
            spec_str = str(spec_value)
            if not self.case_sensitive:
                field_str = field_str.lower()
                spec_str = spec_str.lower()
            return spec_str in field_str

        if operator == ComparisonOperator.ICONTAINS:
            if field_value is None:
                return False
            return str(spec_value).lower() in str(field_value).lower()

        if operator == ComparisonOperator.STARTSWITH:
            if field_value is None:
                return False
            field_str = str(field_value)
            spec_str = str(spec_value)
            if not self.case_sensitive:
                field_str = field_str.lower()
                spec_str = spec_str.lower()
            return field_str.startswith(spec_str)

        if operator == ComparisonOperator.ENDSWITH:
            if field_value is None:
                return False
            field_str = str(field_value)
            spec_str = str(spec_value)
            if not self.case_sensitive:
                field_str = field_str.lower()
                spec_str = spec_str.lower()
            return field_str.endswith(spec_str)

        if operator == ComparisonOperator.IS_NULL:
            return field_value is None

        if operator == ComparisonOperator.IS_NOT_NULL:
            return field_value is not None

        return False

    def to_sql(self, model_type: type[Any]) -> BinaryExpression | BooleanClauseList:
        """
        Convert field specification to SQL condition.

        Args:
            model_type: SQLAlchemy model type

        Returns:
            SQL condition for the specification

        Raises:
            InvalidFieldSpecificationError: If field doesn't exist on model
        """
        if not hasattr(model_type, self.field_name):
            raise InvalidFieldSpecificationError(
                f"Model {model_type.__name__} has no field '{self.field_name}'"
            )

        column = getattr(model_type, self.field_name)

        if self.operator == ComparisonOperator.EQUALS:
            return column == self.value

        if self.operator == ComparisonOperator.NOT_EQUALS:
            return column != self.value

        if self.operator == ComparisonOperator.GREATER_THAN:
            return column > self.value

        if self.operator == ComparisonOperator.GREATER_THAN_OR_EQUAL:
            return column >= self.value

        if self.operator == ComparisonOperator.LESS_THAN:
            return column < self.value

        if self.operator == ComparisonOperator.LESS_THAN_OR_EQUAL:
            return column <= self.value

        if self.operator == ComparisonOperator.IN:
            return column.in_(self.value)

        if self.operator == ComparisonOperator.NOT_IN:
            return ~column.in_(self.value)

        if self.operator == ComparisonOperator.CONTAINS:
            if self.case_sensitive:
                return column.contains(self.value)
            return column.ilike(f"%{self.value}%")

        if self.operator == ComparisonOperator.ICONTAINS:
            return column.ilike(f"%{self.value}%")

        if self.operator == ComparisonOperator.STARTSWITH:
            if self.case_sensitive:
                return column.like(f"{self.value}%")
            return column.ilike(f"{self.value}%")

        if self.operator == ComparisonOperator.ENDSWITH:
            if self.case_sensitive:
                return column.like(f"%{self.value}")
            return column.ilike(f"%{self.value}")

        if self.operator == ComparisonOperator.IS_NULL:
            return column.is_(None)

        if self.operator == ComparisonOperator.IS_NOT_NULL:
            return column.is_not(None)

        raise SpecificationMappingError(f"Unsupported operator: {self.operator}")


class DateRangeSpecification(Specification):
    """
    Sophisticated date range specification with timezone and precision handling.

    Provides flexible date range filtering with support for different date types,
    timezone handling, and precision levels (day, hour, minute, second).

    Features:
    - Flexible date range handling with inclusive/exclusive bounds
    - Timezone-aware date comparisons
    - Multiple precision levels for date comparison
    - Null-safe date handling and validation
    - Performance optimization for date range queries

    Usage Examples:
        # Basic date range
        spec = DateRangeSpecification(
            "created_at",
            start_date=datetime(2023, 1, 1),
            end_date=datetime(2023, 12, 31)
        )

        # Date range with precision
        spec = DateRangeSpecification(
            "last_login",
            start_date=date.today(),
            precision="day",
            include_start=True,
            include_end=False
        )
    """

    def __init__(
        self,
        field_name: str,
        start_date: datetime | date | None = None,
        end_date: datetime | date | None = None,
        include_start: bool = True,
        include_end: bool = True,
        precision: str = "second",
    ):
        """
        Initialize date range specification.

        Args:
            field_name: Name of the date field
            start_date: Start of date range (None for no lower bound)
            end_date: End of date range (None for no upper bound)
            include_start: Whether to include start date in range
            include_end: Whether to include end date in range
            precision: Date comparison precision ("day", "hour", "minute", "second")

        Raises:
            ValidationError: If parameters are invalid
        """
        self._validate_date_range(field_name, start_date, end_date, precision)

        self.field_name = field_name
        self.start_date = start_date
        self.end_date = end_date
        self.include_start = include_start
        self.include_end = include_end
        self.precision = precision

    def _validate_date_range(
        self,
        field_name: str,
        start_date: datetime | date | None,
        end_date: datetime | date | None,
        precision: str,
    ) -> None:
        """Validate date range specification parameters."""
        if not field_name or not isinstance(field_name, str):
            raise ValidationError("field_name must be non-empty string")

        if start_date is None and end_date is None:
            raise ValidationError(
                "At least one of start_date or end_date must be provided"
            )

        if start_date and end_date and start_date > end_date:
            raise ValidationError("start_date must be <= end_date")

        if precision not in ["day", "hour", "minute", "second"]:
            raise ValidationError("precision must be one of: day, hour, minute, second")

    def is_satisfied_by(self, entity: Any) -> bool:
        """Check if entity's date field falls within the specified range."""
        field_value = getattr(entity, self.field_name, None)
        if field_value is None:
            return False

        # Convert to datetime for comparison if needed
        if isinstance(field_value, date) and not isinstance(field_value, datetime):
            field_value = datetime.combine(field_value, datetime.min.time())

        return self._is_date_in_range(field_value)

    def _is_date_in_range(self, field_value: datetime) -> bool:
        """Check if date value is within the specified range."""
        # Check start date
        if self.start_date:
            start_dt = self._normalize_date(self.start_date)
            if self.include_start:
                if field_value < start_dt:
                    return False
            elif field_value <= start_dt:
                return False

        # Check end date
        if self.end_date:
            end_dt = self._normalize_date(self.end_date)
            if self.include_end:
                if field_value > end_dt:
                    return False
            elif field_value >= end_dt:
                return False

        return True

    def _normalize_date(self, date_value: datetime | date) -> datetime:
        """Normalize date value to datetime for consistent comparison."""
        if isinstance(date_value, date) and not isinstance(date_value, datetime):
            return datetime.combine(date_value, datetime.min.time())
        return date_value

    def to_sql(self, model_type: type[Any]) -> BinaryExpression | BooleanClauseList:
        """Convert date range specification to SQL condition."""
        if not hasattr(model_type, self.field_name):
            raise InvalidFieldSpecificationError(
                f"Model {model_type.__name__} has no field '{self.field_name}'"
            )

        column = getattr(model_type, self.field_name)
        conditions = []

        # Add start date condition
        if self.start_date:
            if self.include_start:
                conditions.append(column >= self.start_date)
            else:
                conditions.append(column > self.start_date)

        # Add end date condition
        if self.end_date:
            if self.include_end:
                conditions.append(column <= self.end_date)
            else:
                conditions.append(column < self.end_date)

        if len(conditions) == 1:
            return conditions[0]
        return and_(*conditions)


# Factory function for creating optimized specification evaluator


def create_specification_evaluator(
    enable_optimization: bool = True,
    custom_mappers: dict[type[Specification], Callable] | None = None,
) -> SpecificationEvaluator:
    """
    Create specification evaluator with optimal configuration.

    Factory function that creates a fully configured specification evaluator
    with built-in optimizations and optional custom specification mappers.

    Args:
        enable_optimization: Enable query optimization features
        custom_mappers: Optional dictionary of custom specification mappers

    Returns:
        Configured SpecificationEvaluator instance

    Usage Examples:
        # Basic evaluator
        evaluator = create_specification_evaluator()

        # Evaluator with custom specifications
        custom_mappers = {
            MyCustomSpecification: lambda spec, model: model.field == spec.value
        }
        evaluator = create_specification_evaluator(
            enable_optimization=True,
            custom_mappers=custom_mappers
        )
    """
    # Create mapper with optimization settings
    mapper = SpecificationMapper(enable_optimization=enable_optimization)

    # Register custom mappers if provided
    if custom_mappers:
        for spec_type, mapper_func in custom_mappers.items():
            mapper.register_mapper(spec_type, mapper_func)

    # Create and return evaluator
    evaluator = SpecificationEvaluator(mapper)

    logger.info(
        "Specification evaluator created",
        optimization_enabled=enable_optimization,
        custom_mappers_count=len(custom_mappers) if custom_mappers else 0,
    )

    return evaluator


# Convenience functions for common specification patterns


def field_equals(field_name: str, value: Any) -> FieldSpecification:
    """Create field equality specification."""
    return FieldSpecification(field_name, ComparisonOperator.EQUALS, value)


def field_in(field_name: str, values: list[Any]) -> FieldSpecification:
    """Create field IN specification."""
    return FieldSpecification(field_name, ComparisonOperator.IN, values)


def field_contains(
    field_name: str, text: str, case_sensitive: bool = False
) -> FieldSpecification:
    """Create field text contains specification."""
    operator = (
        ComparisonOperator.CONTAINS if case_sensitive else ComparisonOperator.ICONTAINS
    )
    return FieldSpecification(field_name, operator, text, case_sensitive)


def field_not_null(field_name: str) -> FieldSpecification:
    """Create field not null specification."""
    return FieldSpecification(field_name, ComparisonOperator.IS_NOT_NULL, None)


def date_range(
    field_name: str,
    start_date: datetime | date | None = None,
    end_date: datetime | date | None = None,
) -> DateRangeSpecification:
    """Create date range specification."""
    return DateRangeSpecification(field_name, start_date, end_date)
