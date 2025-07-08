"""Specification pattern implementation following pure Python principles.

This module provides a comprehensive implementation of the Specification pattern
for domain-driven design, completely framework-agnostic and following clean
architecture principles.

The Specification pattern allows business rules to be recombined in different
ways, enabling flexible and maintainable domain logic. This implementation
provides rich functionality for composing, validating, and testing specifications.

Design Principles:
- Pure Python classes with no framework dependencies
- Composable specifications (AND, OR, NOT operations)
- Rich error messaging and validation support
- Generic type support for type safety
- Performance optimizations for complex specifications
- Comprehensive testing utilities

Architecture:
- Specification: Base abstract class for business rules
- CompositeSpecification: Base for specifications that combine others
- Concrete implementations: AndSpecification, OrSpecification, NotSpecification
- Validation utilities: For testing and validation
- Performance utilities: For optimization and monitoring
"""

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from app.core.errors import DomainError, ValidationError

# Type variable for specifications
T = TypeVar("T")


# =====================================================================================
# BASE SPECIFICATION CLASSES
# =====================================================================================


class Specification(ABC, Generic[T]):
    """
    Base specification class following pure Python principles.

    Specifications encapsulate business rules that can be evaluated against
    domain objects. They enable complex business logic to be composed and
    reused across different contexts.

    Design Features:
    - Framework-agnostic implementation
    - Rich composition capabilities (AND, OR, NOT)
    - Comprehensive error handling and messaging
    - Performance monitoring and caching
    - Type safety with generics

    Usage Example:
        class ActiveUserSpecification(Specification[User]):
            def is_satisfied_by(self, user: User) -> bool:
                return user.is_active and not user.is_suspended

            def get_error_message(self, user: User) -> str:
                return f"User {user.id} is not active or is suspended"
    """

    def __init__(self) -> None:
        """Initialize specification with performance tracking."""
        self._evaluation_count = 0
        self._total_evaluation_time = 0.0
        self._cache_enabled = False
        self._cache: dict[Any, bool] = {}

    @abstractmethod
    def is_satisfied_by(self, candidate: T) -> bool:
        """
        Check if candidate satisfies the specification.

        Args:
            candidate: Object to evaluate against the specification

        Returns:
            bool: True if specification is satisfied, False otherwise
        """

    def get_error_message(self, candidate: T) -> str:
        """
        Get error message when specification is not satisfied.

        Default implementation provides generic message. Override for specific messages.

        Args:
            candidate: Object that failed the specification

        Returns:
            str: Error message explaining why specification failed
        """
        return f"{self.__class__.__name__} is not satisfied by {candidate}"

    def and_(self, other: "Specification[T]") -> "AndSpecification[T]":
        """
        Create AND specification combining this with another specification.

        Args:
            other: Specification to combine with

        Returns:
            AndSpecification: New specification that requires both to be satisfied
        """
        return AndSpecification(self, other)

    def or_(self, other: "Specification[T]") -> "OrSpecification[T]":
        """
        Create OR specification combining this with another specification.

        Args:
            other: Specification to combine with

        Returns:
            OrSpecification: New specification that requires either to be satisfied
        """
        return OrSpecification(self, other)

    def not_(self) -> "NotSpecification[T]":
        """
        Create NOT specification that negates this specification.

        Returns:
            NotSpecification: New specification that negates this one
        """
        return NotSpecification(self)

    def validate(self, candidate: T) -> None:
        """
        Validate candidate against specification.

        Args:
            candidate: Object to validate

        Raises:
            DomainError: If specification is not satisfied
        """
        if not self.evaluate(candidate):
            raise DomainError(self.get_error_message(candidate))

    def evaluate(self, candidate: T) -> bool:
        """
        Evaluate specification with performance tracking and optional caching.

        Args:
            candidate: Object to evaluate

        Returns:
            bool: True if specification is satisfied
        """
        # Check cache first if enabled
        if self._cache_enabled:
            cache_key = self._get_cache_key(candidate)
            if cache_key in self._cache:
                return self._cache[cache_key]

        # Perform evaluation with timing
        start_time = time.time()
        try:
            result = self.is_satisfied_by(candidate)
        finally:
            evaluation_time = time.time() - start_time
            self._evaluation_count += 1
            self._total_evaluation_time += evaluation_time

        # Cache result if caching is enabled
        if self._cache_enabled:
            cache_key = self._get_cache_key(candidate)
            self._cache[cache_key] = result

        return result

    def _get_cache_key(self, candidate: T) -> Any:
        """
        Get cache key for candidate. Override for custom caching logic.

        Args:
            candidate: Object to get cache key for

        Returns:
            Any: Cache key (must be hashable)
        """
        if hasattr(candidate, "id"):
            return f"{self.__class__.__name__}:{candidate.id}"
        return f"{self.__class__.__name__}:{hash(candidate)}"

    def enable_caching(self) -> None:
        """Enable result caching for performance optimization."""
        self._cache_enabled = True
        self._cache = {}

    def disable_caching(self) -> None:
        """Disable result caching and clear cache."""
        self._cache_enabled = False
        self._cache = {}

    def clear_cache(self) -> None:
        """Clear the evaluation cache."""
        self._cache = {}

    @property
    def evaluation_count(self) -> int:
        """Get number of times this specification has been evaluated."""
        return self._evaluation_count

    @property
    def average_evaluation_time(self) -> float:
        """Get average evaluation time in seconds."""
        if self._evaluation_count == 0:
            return 0.0
        return self._total_evaluation_time / self._evaluation_count

    def get_performance_stats(self) -> dict[str, Any]:
        """
        Get performance statistics for this specification.

        Returns:
            dict[str, Any]: Performance statistics
        """
        return {
            "specification_class": self.__class__.__name__,
            "evaluation_count": self._evaluation_count,
            "total_evaluation_time": self._total_evaluation_time,
            "average_evaluation_time": self.average_evaluation_time,
            "cache_enabled": self._cache_enabled,
            "cache_size": len(self._cache) if self._cache_enabled else 0,
        }

    def __str__(self) -> str:
        """String representation of the specification."""
        return self.__class__.__name__

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"{self.__class__.__name__}(evaluations={self._evaluation_count})"


class CompositeSpecification(Specification[T]):
    """
    Base class for composite specifications that combine multiple specifications.

    Provides common functionality for specifications that combine other
    specifications (AND, OR, etc.) including performance optimization
    and error message composition.
    """

    def __init__(self, *specifications: Specification[T]):
        """
        Initialize composite specification.

        Args:
            specifications: Specifications to compose
        """
        super().__init__()
        self.specifications = list(specifications)
        self._validate_specifications()

    def _validate_specifications(self) -> None:
        """Validate that all child specifications are valid."""
        if not self.specifications:
            raise ValidationError(
                "Composite specification must have at least one child specification"
            )

        for spec in self.specifications:
            if not isinstance(spec, Specification):
                raise ValidationError(
                    "All child specifications must be Specification instances"
                )

    def get_child_specifications(self) -> list[Specification[T]]:
        """
        Get list of child specifications.

        Returns:
            list[Specification[T]]: List of child specifications
        """
        return self.specifications.copy()

    def get_performance_stats(self) -> dict[str, Any]:
        """Get comprehensive performance statistics including child specifications."""
        stats = super().get_performance_stats()
        stats["child_specifications"] = [
            spec.get_performance_stats() for spec in self.specifications
        ]
        return stats


# =====================================================================================
# CONCRETE SPECIFICATION IMPLEMENTATIONS
# =====================================================================================


class AndSpecification(CompositeSpecification[T]):
    """
    AND composite specification that requires all child specifications to be satisfied.

    Implements short-circuit evaluation for performance optimization - evaluation
    stops as soon as one specification fails.
    """

    def __init__(self, left: Specification[T], right: Specification[T]):
        """
        Initialize AND specification.

        Args:
            left: First specification
            right: Second specification
        """
        super().__init__(left, right)
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        """
        Check if candidate satisfies both specifications.

        Uses short-circuit evaluation for performance.

        Args:
            candidate: Object to evaluate

        Returns:
            bool: True only if both specifications are satisfied
        """
        # Short-circuit evaluation - if left fails, don't evaluate right
        return self.left.evaluate(candidate) and self.right.evaluate(candidate)

    def get_error_message(self, candidate: T) -> str:
        """Get combined error message from both specifications."""
        messages = []

        if not self.left.evaluate(candidate):
            messages.append(self.left.get_error_message(candidate))

        if not self.right.evaluate(candidate):
            messages.append(self.right.get_error_message(candidate))

        if not messages:
            return f"AND specification satisfied for {candidate}"

        return " AND ".join(messages)

    def __str__(self) -> str:
        return f"({self.left} AND {self.right})"


class OrSpecification(CompositeSpecification[T]):
    """
    OR composite specification that requires at least one child specification to be satisfied.

    Implements short-circuit evaluation for performance optimization - evaluation
    stops as soon as one specification succeeds.
    """

    def __init__(self, left: Specification[T], right: Specification[T]):
        """
        Initialize OR specification.

        Args:
            left: First specification
            right: Second specification
        """
        super().__init__(left, right)
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        """
        Check if candidate satisfies either specification.

        Uses short-circuit evaluation for performance.

        Args:
            candidate: Object to evaluate

        Returns:
            bool: True if either specification is satisfied
        """
        # Short-circuit evaluation - if left succeeds, don't evaluate right
        return self.left.evaluate(candidate) or self.right.evaluate(candidate)

    def get_error_message(self, candidate: T) -> str:
        """Get combined error message from both specifications."""
        left_msg = self.left.get_error_message(candidate)
        right_msg = self.right.get_error_message(candidate)
        return f"({left_msg}) OR ({right_msg})"

    def __str__(self) -> str:
        return f"({self.left} OR {self.right})"


class NotSpecification(Specification[T]):
    """
    NOT specification that negates another specification.

    Returns true when the wrapped specification returns false, and vice versa.
    """

    def __init__(self, spec: Specification[T]):
        """
        Initialize NOT specification.

        Args:
            spec: Specification to negate
        """
        super().__init__()
        self.spec = spec

        if not isinstance(spec, Specification):
            raise ValidationError(
                "NOT specification requires a valid Specification instance"
            )

    def is_satisfied_by(self, candidate: T) -> bool:
        """
        Check if candidate does NOT satisfy the wrapped specification.

        Args:
            candidate: Object to evaluate

        Returns:
            bool: True if wrapped specification is NOT satisfied
        """
        return not self.spec.evaluate(candidate)

    def get_error_message(self, candidate: T) -> str:
        """Get negated error message."""
        return f"NOT ({self.spec.get_error_message(candidate)})"

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics including wrapped specification."""
        stats = super().get_performance_stats()
        stats["wrapped_specification"] = self.spec.get_performance_stats()
        return stats

    def __str__(self) -> str:
        return f"NOT {self.spec}"


class TrueSpecification(Specification[T]):
    """Always satisfied specification - useful for testing and composition."""

    def is_satisfied_by(self, candidate: T) -> bool:
        """Always returns True."""
        return True

    def get_error_message(self, candidate: T) -> str:
        """This specification never fails, so this should never be called."""
        return "TrueSpecification should never fail"

    def __str__(self) -> str:
        return "TRUE"


class FalseSpecification(Specification[T]):
    """Never satisfied specification - useful for testing and composition."""

    def is_satisfied_by(self, candidate: T) -> bool:
        """Always returns False."""
        return False

    def get_error_message(self, candidate: T) -> str:
        """Always returns failure message."""
        return f"FalseSpecification always fails for {candidate}"

    def __str__(self) -> str:
        return "FALSE"


# =====================================================================================
# UTILITY SPECIFICATIONS
# =====================================================================================


class LambdaSpecification(Specification[T]):
    """
    Specification that wraps a lambda function for simple specifications.

    Useful for creating specifications on-the-fly without creating new classes.
    """

    def __init__(
        self, predicate: Callable[[T], bool], error_message: str | None = None
    ):
        """
        Initialize lambda specification.

        Args:
            predicate: Function that takes candidate and returns bool
            error_message: Optional custom error message
        """
        super().__init__()

        if not callable(predicate):
            raise ValidationError("Predicate must be callable")

        self.predicate = predicate
        self.custom_error_message = error_message

    def is_satisfied_by(self, candidate: T) -> bool:
        """Evaluate using the lambda function."""
        try:
            return self.predicate(candidate)
        except Exception as e:
            raise DomainError(f"Error evaluating lambda specification: {e!s}") from e

    def get_error_message(self, candidate: T) -> str:
        """Get custom or default error message."""
        if self.custom_error_message:
            return self.custom_error_message
        return f"Lambda specification failed for {candidate}"

    def __str__(self) -> str:
        return f"Lambda({self.predicate.__name__ if hasattr(self.predicate, '__name__') else 'anonymous'})"


class CollectionSpecification(Specification[T]):
    """
    Specification for collections that applies child specification to all/any items.
    """

    def __init__(self, item_spec: Specification[Any], require_all: bool = True):
        """
        Initialize collection specification.

        Args:
            item_spec: Specification to apply to collection items
            require_all: If True, all items must satisfy spec; if False, at least one must
        """
        super().__init__()
        self.item_spec = item_spec
        self.require_all = require_all

    def is_satisfied_by(self, candidate: T) -> bool:
        """Evaluate specification against collection items."""
        if not hasattr(candidate, "__iter__"):
            raise DomainError(
                f"CollectionSpecification requires iterable, got {type(candidate)}"
            )

        items = list(candidate)

        if not items:
            return True  # Empty collection satisfies any collection specification

        if self.require_all:
            return all(self.item_spec.evaluate(item) for item in items)
        return any(self.item_spec.evaluate(item) for item in items)

    def get_error_message(self, candidate: T) -> str:
        """Get error message for collection specification."""
        quantifier = "all" if self.require_all else "any"
        return f"Collection specification requires {quantifier} items to satisfy: {self.item_spec}"

    def __str__(self) -> str:
        quantifier = "ALL" if self.require_all else "ANY"
        return f"{quantifier}({self.item_spec})"


# =====================================================================================
# SPECIFICATION UTILITIES
# =====================================================================================


class SpecificationValidator:
    """Utility class for validating and testing specifications."""

    @staticmethod
    def validate_specification_tree(spec: Specification[Any]) -> list[str]:
        """
        Validate a specification tree for common issues.

        Args:
            spec: Root specification to validate

        Returns:
            list[str]: List of validation issues (empty if valid)
        """
        issues = []
        visited = set()

        def _validate_recursive(
            current_spec: Specification[Any], depth: int = 0
        ) -> None:
            # Check for infinite recursion
            spec_id = id(current_spec)
            if spec_id in visited:
                issues.append("Circular reference detected in specification tree")
                return

            visited.add(spec_id)

            # Check depth to prevent stack overflow
            if depth > 100:
                issues.append("Specification tree too deep (>100 levels)")
                return

            # Validate specific specification types
            if isinstance(current_spec, CompositeSpecification):
                if not current_spec.specifications:
                    issues.append("Composite specification has no child specifications")

                for child_spec in current_spec.specifications:
                    _validate_recursive(child_spec, depth + 1)

            elif isinstance(current_spec, NotSpecification):
                _validate_recursive(current_spec.spec, depth + 1)

        _validate_recursive(spec)
        return issues

    @staticmethod
    def benchmark_specification(
        spec: Specification[T], candidates: list[T], iterations: int = 1000
    ) -> dict[str, Any]:
        """
        Benchmark specification performance.

        Args:
            spec: Specification to benchmark
            candidates: List of candidates to test against
            iterations: Number of iterations to run

        Returns:
            dict[str, Any]: Benchmark results
        """
        if not candidates:
            raise ValidationError(
                "Must provide at least one candidate for benchmarking"
            )

        start_time = time.time()
        results = []

        for _ in range(iterations):
            for candidate in candidates:
                result = spec.evaluate(candidate)
                results.append(result)

        end_time = time.time()
        total_time = end_time - start_time
        total_evaluations = iterations * len(candidates)

        return {
            "total_time": total_time,
            "total_evaluations": total_evaluations,
            "evaluations_per_second": total_evaluations / total_time,
            "average_time_per_evaluation": total_time / total_evaluations,
            "true_results": sum(results),
            "false_results": len(results) - sum(results),
            "specification_stats": spec.get_performance_stats(),
        }


def create_lambda_spec(
    predicate: Callable[[T], bool], error_message: str | None = None
) -> LambdaSpecification[T]:
    """
    Convenience function to create lambda specifications.

    Args:
        predicate: Function that takes candidate and returns bool
        error_message: Optional custom error message

    Returns:
        LambdaSpecification: New lambda specification
    """
    return LambdaSpecification(predicate, error_message)


def all_satisfy(item_spec: Specification[Any]) -> CollectionSpecification[Any]:
    """
    Create specification that requires all collection items to satisfy child specification.

    Args:
        item_spec: Specification for individual items

    Returns:
        CollectionSpecification: New collection specification (all mode)
    """
    return CollectionSpecification(item_spec, require_all=True)


def any_satisfy(item_spec: Specification[Any]) -> CollectionSpecification[Any]:
    """
    Create specification that requires at least one collection item to satisfy child specification.

    Args:
        item_spec: Specification for individual items

    Returns:
        CollectionSpecification: New collection specification (any mode)
    """
    return CollectionSpecification(item_spec, require_all=False)


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    # Concrete implementations
    "AndSpecification",
    "CollectionSpecification",
    "CompositeSpecification",
    "FalseSpecification",
    # Utility specifications
    "LambdaSpecification",
    "NotSpecification",
    "OrSpecification",
    # Base classes
    "Specification",
    # Utilities
    "SpecificationValidator",
    "TrueSpecification",
    "all_satisfy",
    "any_satisfy",
    "create_lambda_spec",
]
