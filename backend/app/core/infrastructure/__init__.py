"""
Infrastructure layer components for data access and persistence.

This module provides comprehensive infrastructure components for building
robust, scalable applications with proper separation of concerns.

Components:
- Repository Pattern: Domain-driven data access abstractions
- Unit of Work: Transaction management and coordination
- Persistence: SQLAlchemy-based ORM models and mixins
- Caching: Performance optimization through intelligent caching
- Event Sourcing: Domain event handling and storage

Usage:
    from app.core.infrastructure import BaseRepository, BaseUnitOfWork
    from app.core.infrastructure.persistence.base import BaseModel, AuditMixin
    
    class UserRepository(BaseRepository[User, UUID]):
        # Implementation specific to your domain
        pass
"""

# Repository pattern components
try:
    from app.core.infrastructure.repository import (
        BaseRepository,
        CacheableRepository,
        EventSourcedRepository,
        ReadOnlyRepository,
        Repository,
        RepositoryFactory,
        SpecificationRepository,
        TransactionalRepository,
        TransactionContext,
        WriteOnlyRepository,
    )
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import repository components: {e}", ImportWarning, stacklevel=2)
    
    # Provide minimal fallback
    class BaseRepository:
        """Fallback repository base class."""
        def __init__(self, *args, **kwargs):
            pass
        
        async def get(self, id):
            raise NotImplementedError("Repository not available")
        
        async def save(self, entity):
            raise NotImplementedError("Repository not available")
    
    Repository = BaseRepository
    SpecificationRepository = BaseRepository
    CacheableRepository = BaseRepository
    EventSourcedRepository = BaseRepository
    TransactionalRepository = BaseRepository
    ReadOnlyRepository = BaseRepository
    WriteOnlyRepository = BaseRepository
    
    class RepositoryFactory:
        """Fallback repository factory."""
    
    class TransactionContext:
        """Fallback transaction context."""

# Unit of Work pattern
try:
    from app.core.infrastructure.unit_of_work import BaseUnitOfWork
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import unit of work: {e}", ImportWarning, stacklevel=2)
    
    class BaseUnitOfWork:
        """Fallback unit of work class."""
        def __init__(self, *args, **kwargs):
            pass
        
        async def __aenter__(self):
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        
        async def commit(self):
            pass
        
        async def rollback(self):
            pass

# Persistence layer components
try:
    from app.core.infrastructure.persistence.base import (
        AuditableModel,
        AuditMixin,
        BaseModel,
        EnhancedJSONType,
        FullAuditModel,
        MetadataMixin,
        ModelValidationError,
        OptimisticLockError,
        PersistenceError,
        SoftDeletableModel,
        SoftDeleteError,
        SoftDeleteMixin,
        VersionedMixin,
        VersionedModel,
        bulk_restore,
        bulk_soft_delete,
        monitor_query_performance,
    )
except ImportError as e:
    import warnings
    warnings.warn(f"Failed to import persistence components: {e}", ImportWarning, stacklevel=2)
    
    # Provide minimal fallbacks
    class BaseModel:
        """Fallback base model class."""
        def __init__(self, *args, **kwargs):
            pass
    
    class PersistenceError(Exception):
        """Fallback persistence error."""
    
    class OptimisticLockError(PersistenceError):
        """Fallback optimistic lock error."""
    
    class SoftDeleteError(PersistenceError):
        """Fallback soft delete error."""
    
    class ModelValidationError(PersistenceError):
        """Fallback model validation error."""
    
    # Fallback mixins
    AuditMixin = BaseModel
    SoftDeleteMixin = BaseModel
    VersionedMixin = BaseModel
    MetadataMixin = BaseModel
    AuditableModel = BaseModel
    SoftDeletableModel = BaseModel
    VersionedModel = BaseModel
    FullAuditModel = BaseModel
    
    # Fallback types and functions
    EnhancedJSONType = dict
    
    def monitor_query_performance(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    async def bulk_soft_delete(*args, **kwargs):
        pass
    
    async def bulk_restore(*args, **kwargs):
        pass

__all__ = [
    "AuditMixin",
    "AuditableModel",
    # Persistence models
    "BaseModel",
    # Repository pattern
    "BaseRepository",
    # Unit of Work
    "BaseUnitOfWork",
    "CacheableRepository",
    # Persistence utilities
    "EnhancedJSONType",
    "EventSourcedRepository",
    "FullAuditModel",
    "MetadataMixin",
    "ModelValidationError",
    "OptimisticLockError",
    # Exceptions
    "PersistenceError",
    "ReadOnlyRepository",
    "Repository",
    "RepositoryFactory",
    "SoftDeletableModel",
    "SoftDeleteError",
    "SoftDeleteMixin",
    "SpecificationRepository",
    "TransactionContext",
    "TransactionalRepository",
    "VersionedMixin",
    "VersionedModel",
    "WriteOnlyRepository",
    "bulk_restore",
    "bulk_soft_delete",
    "monitor_query_performance",
]

# Version info
__version__ = "1.0.0"
