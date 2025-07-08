"""Core repository interfaces and implementations.

This module provides enhanced repository patterns with specification support,
factory patterns, and dependency injection integration.

Features:
- Base repository interfaces and implementations
- Specification pattern integration
- Advanced query capabilities
- Transaction management
- Repository factory and DI support
"""

# Import base repository components with fallback handling
try:
    from app.core.repositories.base import (
        BaseRepository,
        IRepository,
        IRepositoryFactory,
        ISpecificationRepository,
        IUnitOfWork,
        RepositoryFactory,
        SpecificationRepository,
    )
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import base repository components: {e}", ImportWarning, stacklevel=2)
    # Provide minimal fallback interfaces
    from abc import ABC, abstractmethod
    from typing import Any, Generic, TypeVar
    
    T = TypeVar("T")
    
    class IRepository(ABC, Generic[T]):
        """Fallback repository interface."""
    
    class ISpecificationRepository(IRepository[T]):
        """Fallback specification repository interface."""
    
    class BaseRepository(ISpecificationRepository[T]):
        """Fallback base repository."""

# Import factory components with fallback handling
try:
    from app.core.repositories.factory import (
        RepositoryRegistration,
        configure_repository_factory,
        get_repository_factory,
    )
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import repository factory: {e}", ImportWarning, stacklevel=2)
    
    def configure_repository_factory(*args, **kwargs):
        """Fallback factory configuration."""
    
    def get_repository_factory():
        """Fallback factory getter."""
        return
    
    class RepositoryRegistration:
        """Fallback registration class."""

# Import query components with fallback handling
try:
    from app.core.repositories.query import (
        AggregateFunction,
        CursorInfo,
        IQueryBuilder,
        PageInfo,
        QueryBuilder,
        QueryOptions,
        QueryResult,
        SortDirection,
        SortField,
        create_query,
        filtered_query,
        paginated_query,
        search_query,
        sorted_query,
    )
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import query components: {e}", ImportWarning, stacklevel=2)
    
    # Provide minimal fallback implementations
    from enum import Enum
    
    class SortDirection(Enum):
        ASC = "asc"
        DESC = "desc"
    
    class AggregateFunction(Enum):
        COUNT = "count"
        SUM = "sum"
        AVG = "avg"
    
    def create_query():
        """Fallback query creator."""
        return

# Import transaction components with fallback handling
try:
    from app.core.repositories.transaction import (
        ITransactionManager,
        TransactionError,
        TransactionManager,
        TransactionScope,
        UnitOfWork,
        transaction_scope,
        unit_of_work,
    )
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import transaction components: {e}", ImportWarning, stacklevel=2)
    
    class TransactionError(Exception):
        """Fallback transaction error."""
    
    def transaction_scope(*args, **kwargs):
        """Fallback transaction scope."""
    
    def unit_of_work(*args, **kwargs):
        """Fallback unit of work."""

__all__ = [
    "AggregateFunction",
    # Base implementations
    "BaseRepository",
    "CursorInfo",
    "IQueryBuilder",
    # Base interfaces
    "IRepository",
    "IRepositoryFactory",
    "ISpecificationRepository",
    # Transaction management
    "ITransactionManager",
    "IUnitOfWork",
    "PageInfo",
    "QueryBuilder",
    "QueryOptions",
    "QueryResult",
    "RepositoryFactory",
    # Factory
    "RepositoryRegistration",
    # Query capabilities
    "SortDirection",
    "SortField",
    "SpecificationRepository",
    "TransactionError",
    "TransactionManager",
    "TransactionScope",
    "UnitOfWork",
    "configure_repository_factory",
    "create_query",
    "filtered_query",
    "get_repository_factory",
    "paginated_query",
    "search_query",
    "sorted_query",
    "transaction_scope",
    "unit_of_work",
]
