"""
Base Specification Classes

Provides common functionality for all domain specifications.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from functools import lru_cache
from typing import Generic, TypeVar

T = TypeVar('T')


class BaseSpecification(ABC, Generic[T]):
    """
    Base specification class with common functionality.
    
    Provides caching, validation, and composition capabilities.
    """
    
    def __init__(self):
        self._cache_enabled = True
        self._validation_enabled = True
    
    @abstractmethod
    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies the specification."""
    
    def and_(self, other: 'BaseSpecification[T]') -> 'AndSpecification[T]':
        """Combine with another specification using AND logic."""
        return AndSpecification(self, other)
    
    def or_(self, other: 'BaseSpecification[T]') -> 'OrSpecification[T]':
        """Combine with another specification using OR logic."""
        return OrSpecification(self, other)
    
    def not_(self) -> 'NotSpecification[T]':
        """Negate this specification."""
        return NotSpecification(self)
    
    def validate_candidate(self, candidate: T) -> None:
        """Validate candidate before evaluation."""
        if not self._validation_enabled:
            return
        
        if candidate is None:
            raise ValueError("Candidate cannot be None")
    
    def with_caching(self, enabled: bool = True) -> 'BaseSpecification[T]':
        """Enable or disable caching for this specification."""
        self._cache_enabled = enabled
        return self
    
    def with_validation(self, enabled: bool = True) -> 'BaseSpecification[T]':
        """Enable or disable validation for this specification."""
        self._validation_enabled = enabled
        return self
    
    def __call__(self, candidate: T) -> bool:
        """Allow specification to be called as a function."""
        return self.is_satisfied_by(candidate)


class AndSpecification(BaseSpecification[T]):
    """Specification that combines two specifications with AND logic."""
    
    def __init__(self, left: BaseSpecification[T], right: BaseSpecification[T]):
        super().__init__()
        self.left = left
        self.right = right
    
    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies both specifications."""
        self.validate_candidate(candidate)
        return self.left.is_satisfied_by(candidate) and self.right.is_satisfied_by(candidate)


class OrSpecification(BaseSpecification[T]):
    """Specification that combines two specifications with OR logic."""
    
    def __init__(self, left: BaseSpecification[T], right: BaseSpecification[T]):
        super().__init__()
        self.left = left
        self.right = right
    
    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies either specification."""
        self.validate_candidate(candidate)
        return self.left.is_satisfied_by(candidate) or self.right.is_satisfied_by(candidate)


class NotSpecification(BaseSpecification[T]):
    """Specification that negates another specification."""
    
    def __init__(self, spec: BaseSpecification[T]):
        super().__init__()
        self.spec = spec
    
    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate does NOT satisfy the specification."""
        self.validate_candidate(candidate)
        return not self.spec.is_satisfied_by(candidate)


class CachedSpecification(BaseSpecification[T]):
    """Base class for specifications that benefit from caching."""
    
    def __init__(self, cache_size: int = 128):
        super().__init__()
        self._cache_size = cache_size
    
    @lru_cache(maxsize=128)
    def _cached_evaluation(self, candidate_key: str) -> bool:
        """Cached evaluation method - override in subclasses."""
        raise NotImplementedError("Subclasses must implement _cached_evaluation")
    
    def _get_cache_key(self, candidate: T) -> str:
        """Generate cache key for candidate."""
        if hasattr(candidate, 'id'):
            return f"{candidate.__class__.__name__}:{candidate.id}"
        return f"{candidate.__class__.__name__}:{hash(str(candidate))}"


class TimeBasedSpecification(BaseSpecification[T]):
    """Base class for time-based specifications."""
    
    def __init__(self):
        super().__init__()
        self._current_time = None
    
    def with_time(self, current_time: datetime) -> 'TimeBasedSpecification[T]':
        """Set the current time for testing purposes."""
        self._current_time = current_time
        return self
    
    def get_current_time(self) -> datetime:
        """Get current time (or test time if set)."""
        return self._current_time or datetime.now(UTC)


class ParameterizedSpecification(BaseSpecification[T]):
    """Base class for specifications with parameters."""
    
    def __init__(self, **parameters):
        super().__init__()
        self.parameters = parameters
        self._validate_parameters()
    
    def _validate_parameters(self) -> None:
        """Validate specification parameters."""
        # Override in subclasses
    
    def with_parameters(self, **parameters) -> 'ParameterizedSpecification[T]':
        """Create new specification with updated parameters."""
        new_params = {**self.parameters, **parameters}
        return self.__class__(**new_params)
