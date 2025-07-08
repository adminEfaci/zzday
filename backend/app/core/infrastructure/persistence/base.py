import asyncio
import collections.abc
import ipaddress
import json
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Index, Integer, String, event, func, inspect, text
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, Query, Session, mapped_column
from sqlalchemy.types import TEXT, TypeDecorator

from app.core.errors import InfrastructureError, ValidationError
from app.core.logging import get_logger

# Handle optional monitoring dependency
try:
    from app.core.monitoring import metrics
except ImportError:
    # Fallback metrics implementation
    class MockMetrics:
        def __init__(self):
            self.database_query_duration = MockCounter()
            self.database_query_errors = MockCounter()
    
    class MockCounter:
        def labels(self, **kwargs):
            return self
        def observe(self, value):
            pass
        def inc(self):
            pass
    
    metrics = MockMetrics()

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)

T = TypeVar("T", bound="BaseModel")


def _now_utc() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.utcnow().replace(tzinfo=UTC)


class PersistenceError(InfrastructureError):
    """Base exception for persistence operation failures."""


class OptimisticLockError(PersistenceError):
    """Raised when optimistic locking version conflicts occur."""


class SoftDeleteError(PersistenceError):
    """Raised when soft deletion operations fail."""


class ModelValidationError(ValidationError):
    """Raised when model validation fails."""


class DatabaseCompatibilityError(PersistenceError):
    """Raised when database-specific features are not supported."""


class EnhancedJSONType(TypeDecorator):
    """
    Enhanced JSON type with validation and performance optimization.

    Provides robust JSON serialization/deserialization with comprehensive
    error handling, validation, and performance optimization for different
    database backends.
    """

    impl = TEXT
    cache_ok = True

    def __init__(self, max_size_kb: int | None = None, **kwargs):
        """
        Initialize enhanced JSON type.

        Args:
            max_size_kb: Maximum JSON size in KB (None for unlimited)
            **kwargs: Additional SQLAlchemy type arguments
        """
        super().__init__(**kwargs)
        self.max_size_kb = max_size_kb

    def process_bind_param(self, value: Any, dialect) -> str | None:
        """
        Serialize Python value to JSON string for DB storage.

        Args:
            value: Python value to serialize
            dialect: SQLAlchemy dialect

        Returns:
            Serialized JSON string or None

        Raises:
            ValidationError: If JSON serialization fails or size exceeds limit
        """
        if value is None:
            return None

        try:
            start_time = time.time()
            json_str = json.dumps(value, ensure_ascii=False, separators=(",", ":"))

            # Check size limit if specified
            if self.max_size_kb:
                size_kb = len(json_str.encode("utf-8")) / 1024
                if size_kb > self.max_size_kb:
                    raise ValidationError(
                        f"JSON size {size_kb:.1f}KB exceeds limit of {self.max_size_kb}KB"
                    )

            # Track serialization metrics
            serialization_time = time.time() - start_time
            if serialization_time > 0.1:  # Log slow serialization
                logger.warning(
                    "Slow JSON serialization detected",
                    serialization_time=serialization_time,
                    json_size_bytes=len(json_str),
                )

            return json_str

        except (TypeError, ValueError) as e:
            raise ValidationError(f"JSON serialization failed: {e}")

    def process_result_value(self, value: str | None, dialect) -> Any:
        """
        Deserialize JSON string from DB to Python value.

        Args:
            value: JSON string from database
            dialect: SQLAlchemy dialect

        Returns:
            Deserialized Python value or None

        Raises:
            ValidationError: If JSON deserialization fails
        """
        if value is None:
            return None

        try:
            start_time = time.time()
            result = json.loads(value)

            # Track deserialization metrics
            deserialization_time = time.time() - start_time
            if deserialization_time > 0.1:  # Log slow deserialization
                logger.warning(
                    "Slow JSON deserialization detected",
                    deserialization_time=deserialization_time,
                    json_size_bytes=len(value),
                )

            return result

        except (TypeError, ValueError) as e:
            logger.exception(
                "JSON deserialization failed",
                error=str(e),
                json_preview=value[:100] if len(value) > 100 else value,
            )
            raise ValidationError(f"JSON deserialization failed: {e}")


class CustomBase:
    """
    Custom declarative base with intelligent features:
    - Intelligent table name generation from class names
    - Comprehensive string representation with key fields
    - Type-safe dictionary conversion with exclusion support
    - Intelligent field updates with validation
    - Performance optimization for large models
    """

    @declared_attr
    def __tablename__(self) -> str:
        """
        Generate intelligent table name from class name.

        Converts CamelCase class names to snake_case table names with
        intelligent handling of common patterns and abbreviations.

        Returns:
            Snake-case table name
        """
        name = self.__name__

        # Remove common suffixes
        for suffix in ["Model", "Entity", "Table"]:
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break

        # Handle common abbreviations
        abbreviations = {
            "API": "api",
            "HTTP": "http",
            "XML": "xml",
            "JSON": "json",
            "URL": "url",
            "URI": "uri",
            "UUID": "uuid",
            "ID": "id",
        }

        # Convert to snake_case
        result = []
        i = 0
        while i < len(name):
            char = name[i]

            # Check for abbreviations
            for abbrev, replacement in abbreviations.items():
                if name[i:].startswith(abbrev) and (
                    i + len(abbrev) >= len(name) or name[i + len(abbrev)].isupper()
                ):
                    if result and result[-1] != "_":
                        result.append("_")
                    result.append(replacement)
                    i += len(abbrev)
                    break
            else:
                # Regular character processing
                if (
                    i > 0
                    and char.isupper()
                    and (
                        (i + 1 < len(name) and name[i + 1].islower())
                        or name[i - 1].islower()
                    )
                ):
                    result.append("_")
                result.append(char.lower())
                i += 1

        table_name = "".join(result)

        logger.debug(
            "Generated table name", class_name=self.__name__, table_name=table_name
        )

        return table_name

    def __repr__(self) -> str:
        """
        Create comprehensive string representation showing key identifying fields.
        
        Returns:
            String representation with most relevant fields
        """
        # Prioritized list of fields to show
        priority_fields = [
            "id",
            "uuid",
            "email",
            "username",
            "name",
            "title",
            "slug",
            "code",
        ]
        secondary_fields = ["status", "type", "category", "created_at"]

        attrs = []

        # Add priority fields first
        for field in priority_fields:
            if hasattr(self, field):
                value = getattr(self, field)
                if value is not None:
                    if isinstance(value, str) and len(value) > 50:
                        value = f"{value[:47]}..."
                    attrs.append(f"{field}={value!r}")
                    if len(attrs) >= 3:  # Limit primary fields
                        break

        # Add secondary fields if space allows
        if len(attrs) < 2:
            for field in secondary_fields:
                if hasattr(self, field):
                    value = getattr(self, field)
                    if value is not None:
                        attrs.append(f"{field}={value!r}")
                        if len(attrs) >= 3:
                            break

        # Fallback to ID if nothing else found
        if not attrs and hasattr(self, "id"):
            attrs.append(f"id={getattr(self, 'id', 'unknown')!r}")

        attr_str = ", ".join(attrs) if attrs else "no_identifying_fields"
        return f"<{self.__class__.__name__}({attr_str})>"

    def to_dict(
        self,
        exclude: set[str] | None = None,
        include_relationships: bool = False,
        date_format: str = "iso",
    ) -> dict[str, Any]:
        """
        Convert model to dictionary with advanced options.

        Args:
            exclude: Set of field names to exclude from output
            include_relationships: Whether to include related objects
            date_format: Format for datetime serialization

        Returns:
            Dictionary representation of the model

        Raises:
            ValidationError: If serialization fails
        """
        exclude = exclude or set()
        exclude.add("_sa_instance_state")  # Always exclude SQLAlchemy internal

        result = {}

        try:
            # Process table columns
            for column in self.__table__.columns:
                if column.name in exclude:
                    continue

                value = getattr(self, column.name)
                result[column.name] = self._serialize_value(value, date_format)

            # Process relationships if requested
            if include_relationships:
                mapper = inspect(self.__class__)
                for relationship in mapper.relationships:
                    if relationship.key in exclude:
                        continue

                    rel_value = getattr(self, relationship.key, None)
                    if rel_value is not None:
                        if hasattr(rel_value, "__iter__") and not isinstance(
                            rel_value, str
                        ):
                            # Collection relationship
                            result[relationship.key] = [
                                item.to_dict(exclude=exclude)
                                if hasattr(item, "to_dict")
                                else str(item)
                                for item in rel_value
                            ]
                        else:
                            # Single relationship
                            result[relationship.key] = (
                                rel_value.to_dict(exclude=exclude)
                                if hasattr(rel_value, "to_dict")
                                else str(rel_value)
                            )

            return result

        except Exception as e:
            logger.exception(
                "Model serialization failed",
                model_class=self.__class__.__name__,
                error=str(e),
            )
            raise ValidationError(f"Model serialization failed: {e}")

    def _serialize_value(self, value: Any, date_format: str) -> Any:
        """
        Serialize individual value with type-specific handling.
        
        Args:
            value: Value to serialize
            date_format: Format for datetime serialization
            
        Returns:
            Serialized value
        """
        if value is None:
            return None

        if isinstance(value, UUID):
            return str(value)

        if isinstance(value, datetime):
            try:
                if date_format == "iso":
                    return value.isoformat()
                if date_format == "timestamp":
                    return value.timestamp()
                if date_format == "date_only":
                    return value.date().isoformat()
                return value.isoformat()
            except (ValueError, OverflowError) as e:
                logger.warning(
                    "Failed to serialize datetime",
                    value=str(value),
                    format=date_format,
                    error=str(e)
                )
                return str(value)

        if isinstance(value, Decimal):
            try:
                return float(value)
            except (ValueError, OverflowError):
                return str(value)

        if hasattr(value, "to_dict") and callable(value.to_dict):
            try:
                return value.to_dict()
            except Exception as e:
                logger.warning(
                    "Failed to serialize object with to_dict",
                    object_type=type(value).__name__,
                    error=str(e)
                )
                return str(value)

        if isinstance(value, list | tuple):
            try:
                return [self._serialize_value(item, date_format) for item in value]
            except Exception as e:
                logger.warning(
                    "Failed to serialize sequence",
                    sequence_type=type(value).__name__,
                    error=str(e)
                )
                return str(value)

        if isinstance(value, dict):
            try:
                return {k: self._serialize_value(v, date_format) for k, v in value.items()}
            except Exception as e:
                logger.warning(
                    "Failed to serialize dictionary",
                    error=str(e)
                )
                return str(value)

        # Handle other common types
        if isinstance(value, int | float | str | bool):
            return value
        
        # Fallback to string representation
        return str(value)

    def update_from_dict(
        self,
        data: dict[str, Any],
        exclude: set[str] | None = None,
        validate_fields: bool = True,
    ) -> set[str]:
        """
        Update model from dictionary with validation and tracking.

        Intelligently updates model fields from dictionary data with
        comprehensive validation, change tracking, and error handling.

        Args:
            data: Dictionary of values to update
            exclude: Field names to exclude from update
            validate_fields: Whether to validate field existence

        Returns:
            Set of field names that were actually changed

        Raises:
            ValidationError: If field validation fails
        """
        exclude = exclude or set()
        # Protect critical fields by default
        exclude.update(["id", "created_at", "updated_at", "version"])

        changed_fields = set()

        for key, value in data.items():
            if key in exclude:
                continue

            if validate_fields and not hasattr(self, key):
                logger.warning(
                    "Attempted to update non-existent field",
                    model_class=self.__class__.__name__,
                    field_name=key,
                )
                continue

            # Get current value for comparison with improved equality check
            current_value = getattr(self, key, None)

            # Deep equality check for complex types
            if self._values_equal(current_value, value):
                continue

            try:
                setattr(self, key, value)
                changed_fields.add(key)
            except Exception as e:
                logger.exception(
                    "Failed to update model field",
                    model_class=self.__class__.__name__,
                    field_name=key,
                    error=str(e),
                )
                raise ValidationError(f"Failed to update field '{key}': {e}")

        if changed_fields:
            logger.debug(
                "Model updated from dictionary",
                model_class=self.__class__.__name__,
                changed_fields=list(changed_fields),
            )

        return changed_fields

    def _values_equal(self, current: Any, new: Any) -> bool:
        """
        Compare values for equality with special handling for complex types.
        
        Args:
            current: Current field value
            new: New value to compare
            
        Returns:
            True if values are equal
        """
        # Handle None cases
        if current is None and new is None:
            return True
        if current is None or new is None:
            return False

        # Handle same object reference
        if current is new:
            return True

        # Handle different types
        if type(current) != type(new):
            # Special case for numeric types
            if isinstance(current, int | float) and isinstance(new, int | float):
                try:
                    return float(current) == float(new)
                except (ValueError, OverflowError):
                    return False
            return False

        # For sequences and mappings, use deep comparison
        if isinstance(current, collections.abc.Mapping) and isinstance(new, collections.abc.Mapping):
            try:
                return json.dumps(current, sort_keys=True, default=str) == json.dumps(new, sort_keys=True, default=str)
            except (TypeError, ValueError):
                # Fallback to key-by-key comparison
                try:
                    if len(current) != len(new):
                        return False
                    for key in current:
                        if key not in new or not self._values_equal(current[key], new[key]):
                            return False
                    return True
                except Exception:
                    return current == new

        if (isinstance(current, collections.abc.Sequence) and isinstance(new, collections.abc.Sequence) and 
            not isinstance(current, str) and not isinstance(new, str)):
            try:
                return json.dumps(current, sort_keys=True, default=str) == json.dumps(new, sort_keys=True, default=str)
            except (TypeError, ValueError):
                # Fallback to element-by-element comparison
                try:
                    if len(current) != len(new):
                        return False
                    for i, item in enumerate(current):
                        if not self._values_equal(item, new[i]):
                            return False
                    return True
                except Exception:
                    return current == new

        # Standard equality for other types
        try:
            return current == new
        except Exception:
            # If comparison fails, they're not equal
            return False

    def validate(self) -> None:
        """
        Validate model instance with comprehensive checks.

        Override in subclasses to provide model-specific validation.
        Base implementation validates required fields and constraints.

        Raises:
            ModelValidationError: If validation fails
        """
        # Validate UUID fields if present
        if hasattr(self, 'id') and self.id is not None:
            if not isinstance(self.id, UUID):
                try:
                    # Try to convert string to UUID
                    if isinstance(self.id, str):
                        self.id = UUID(self.id)
                    else:
                        raise ModelValidationError(f"Invalid ID type: {type(self.id)}")
                except ValueError as e:
                    raise ModelValidationError(f"Invalid UUID format for ID: {e}")

        # Validate timestamp fields
        for field_name in ['created_at', 'updated_at', 'deleted_at']:
            if hasattr(self, field_name):
                field_value = getattr(self, field_name)
                if field_value is not None and not isinstance(field_value, datetime):
                    raise ModelValidationError(
                        f"Field {field_name} must be a datetime object, got {type(field_value)}"
                    )

        logger.debug(
            "Base validation completed",
            model_class=self.__class__.__name__,
            entity_id=str(getattr(self, 'id', 'unknown'))
        )


# Create enhanced declarative base
Base = declarative_base(cls=CustomBase)


class BaseModel(Base):
    """
    Enhanced base model with comprehensive features and optimizations.
    
    Features:
    - UUID primary key with high entropy
    - Automatic timestamp management with timezone support
    - Intelligent indexing strategy for performance
    - Hybrid properties for age calculations
    - Performance-optimized table arguments
    """

    __abstract__ = True

    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        default=uuid4,
        comment="Primary key with high-entropy UUID",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="Creation timestamp with timezone",
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
        comment="Last update timestamp with timezone",
    )

    @declared_attr
    def __table_args__(self):
        """
        Enhanced table arguments with performance optimization.

        Provides intelligent indexing strategy and database-specific
        optimizations for common query patterns.

        Returns:
            Tuple of table arguments including indexes and constraints
        """
        base_args = (
            # Composite index for time-based queries
            Index(
                f"ix_{self.__tablename__}_created_updated",
                "created_at",
                "updated_at",
                postgresql_include=["id"],  # Include ID for index-only scans
            ),
            # Index for recent records (most common query pattern)
            Index(
                f"ix_{self.__tablename__}_recent",
                "updated_at",
                postgresql_where=text("updated_at > (NOW() - INTERVAL '30 days')"),
            ),
        )

        # Add database-specific optimizations
        db_args = {
            "postgresql_with_oids": False,  # Disable OIDs for performance
            "postgresql_autovacuum_enabled": True,
            "postgresql_autovacuum_vacuum_scale_factor": 0.1,
            "postgresql_autovacuum_analyze_scale_factor": 0.05,
        }

        return (*base_args, db_args)

    @hybrid_property
    def age_seconds(self) -> float:
        """
        Calculate entity age in seconds since creation.

        Returns:
            Age in seconds as float
        """
        return (_now_utc() - self.created_at).total_seconds()

    @hybrid_property
    def last_modified_seconds(self) -> float:
        """
        Calculate seconds since last modification.

        Returns:
            Seconds since last update as float
        """
        return (_now_utc() - self.updated_at).total_seconds()

    def touch(self) -> None:
        """
        Update the updated_at timestamp to current time with concurrency safety.

        Useful for marking records as recently accessed or modified
        without changing other fields.
        """
        # Use UTC time for consistency
        self.updated_at = _now_utc()

        logger.debug(
            "Entity timestamp updated",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id),
        )

    def safe_update_timestamp(self, session: Session | None = None, force_flush: bool = False) -> bool:
        """
        Safely update timestamp with optional concurrency handling.

        Updates the updated_at timestamp and optionally flushes to database
        to ensure the change is persisted under concurrent access patterns.

        Args:
            session: Optional SQLAlchemy session for flushing
            force_flush: Whether to force a flush to database

        Returns:
            True if timestamp was updated successfully

        Raises:
            PersistenceError: If timestamp update fails under concurrency
        """
        try:
            old_timestamp = getattr(self, 'updated_at', None)
            self.updated_at = _now_utc()

            if force_flush:
                if session is None and hasattr(self, "_sa_instance_state") and self._sa_instance_state:
                    from sqlalchemy.orm import object_session
                    session = object_session(self)
                
                if session:
                    try:
                        session.flush()
                    except Exception as flush_error:
                        logger.warning(
                            "Failed to flush timestamp update",
                            entity_type=self.__class__.__name__,
                            entity_id=str(getattr(self, 'id', 'unknown')),
                            error=str(flush_error)
                        )
                        # Don't raise here, just log the warning
                        # The timestamp update itself succeeded

            logger.debug(
                "Safe timestamp update completed",
                entity_type=self.__class__.__name__,
                entity_id=str(getattr(self, 'id', 'unknown')),
                old_timestamp=old_timestamp.isoformat() if old_timestamp else None,
                new_timestamp=self.updated_at.isoformat(),
                flushed=force_flush,
            )
            return True

        except Exception as e:
            logger.exception(
                "Safe timestamp update failed",
                entity_type=self.__class__.__name__,
                entity_id=str(getattr(self, 'id', 'unknown')),
                error=str(e),
            )
            raise PersistenceError(f"Failed to safely update timestamp: {e}")

    def is_recently_created(self, hours: int = 24) -> bool:
        """
        Check if entity was created within specified hours.

        Args:
            hours: Number of hours to check against

        Returns:
            True if created within the specified time window
        """
        threshold = _now_utc() - timedelta(hours=hours)
        return self.created_at > threshold

    def is_recently_updated(self, hours: int = 1) -> bool:
        """
        Check if entity was updated within specified hours.

        Args:
            hours: Number of hours to check against

        Returns:
            True if updated within the specified time window
        """
        threshold = _now_utc() - timedelta(hours=hours)
        return self.updated_at > threshold


class SoftDeleteMixin:
    """
    Advanced soft deletion with comprehensive tracking and lifecycle management.
    
    Features:
    - Timestamp-based soft deletion
    - User tracking for audit trails
    - Deletion reason tracking
    - Restoration capabilities
    - Performance-optimized indexes
    - Lifecycle hooks for custom behavior
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
        comment="Soft deletion timestamp",
    )

    deleted_by: Mapped[UUID | None] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        default=None,
        comment="User who performed soft deletion",
    )

    deletion_reason: Mapped[str | None] = mapped_column(
        String(500), nullable=True, comment="Reason for deletion"
    )

    @declared_attr
    def __table_args__(self):
        """Add soft delete optimized indexes."""
        existing = getattr(super(), "__table_args__", ()) or ()
        if isinstance(existing, dict):
            existing = (existing,)

        soft_delete_args = (
            # Partial index for active records (most common query)
            Index(
                f"ix_{self.__tablename__}_active",
                "id",
                postgresql_where=text("deleted_at IS NULL"),
            ),
            # Index for soft deleted records with timestamp
            Index(
                f"ix_{self.__tablename__}_deleted",
                "deleted_at",
                "deleted_by",
                postgresql_where=text("deleted_at IS NOT NULL"),
            ),
        )

        return existing + soft_delete_args

    @hybrid_property
    def is_deleted(self) -> bool:
        """Check if entity is soft deleted."""
        return self.deleted_at is not None

    @is_deleted.expression
    def is_deleted(self):
        """SQL expression for is_deleted property."""
        return self.deleted_at.isnot(None)

    @hybrid_property
    def is_active(self) -> bool:
        """Check if entity is active (not soft deleted)."""
        return self.deleted_at is None

    @is_active.expression
    def is_active(self):
        """SQL expression for is_active property."""
        return self.deleted_at.is_(None)

    def soft_delete(
        self,
        deleted_by: UUID | None = None,
        reason: str | None = None,
        force: bool = False,
    ) -> None:
        """
        Perform soft deletion with comprehensive tracking.

        Marks entity as deleted with timestamp, user tracking, and optional
        reason. Provides validation to prevent double deletion.

        Args:
            deleted_by: UUID of user performing deletion
            reason: Optional reason for deletion
            force: Force deletion even if already deleted

        Raises:
            SoftDeleteError: If entity is already deleted and force=False
        """
        if self.is_deleted and not force:
            raise SoftDeleteError(
                f"Entity {self.__class__.__name__}({self.id}) is already deleted"
            )

        # Validate deletion is allowed
        self._validate_deletion_allowed()

        # Perform soft deletion
        self.deleted_at = _now_utc()
        self.deleted_by = deleted_by
        self.deletion_reason = reason

        # Call lifecycle hook
        self._on_soft_delete()

        logger.info(
            "Entity soft deleted",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id),
            deleted_by=str(deleted_by) if deleted_by else None,
            reason=reason,
            force=force,
        )

    def restore(self, restored_by: UUID | None = None) -> None:
        """
        Restore entity from soft deletion with audit tracking.

        Args:
            restored_by: UUID of user performing restoration

        Raises:
            SoftDeleteError: If entity is not deleted or restoration fails
        """
        if not self.is_deleted:
            raise SoftDeleteError(
                f"Entity {self.__class__.__name__}({self.id}) is not deleted"
            )

        # Validate restoration is allowed
        self._validate_restoration_allowed()

        # Clear deletion fields
        deletion_info = {
            "deleted_at": self.deleted_at,
            "deleted_by": self.deleted_by,
            "deletion_reason": self.deletion_reason,
        }

        self.deleted_at = None
        self.deleted_by = None
        self.deletion_reason = None

        # Call lifecycle hook
        self._on_restore(deletion_info)

        logger.info(
            "Entity restored from soft deletion",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id),
            restored_by=str(restored_by) if restored_by else None,
            previous_deletion=deletion_info,
        )

    def _validate_deletion_allowed(self) -> None:
        """
        Validate that deletion is allowed for this entity.

        Override in subclasses to implement custom validation logic.
        Base implementation allows all deletions.

        Raises:
            SoftDeleteError: If deletion is not allowed
        """
        logger.debug(
            "Deletion validation - override in subclass for custom logic",
            entity_type=self.__class__.__name__
        )

    def _validate_restoration_allowed(self) -> None:
        """
        Validate that restoration is allowed for this entity.

        Override in subclasses to implement custom validation logic.
        Base implementation allows all restorations.

        Raises:
            SoftDeleteError: If restoration is not allowed
        """
        logger.debug(
            "Restoration validation - override in subclass for custom logic",
            entity_type=self.__class__.__name__
        )

    def _on_soft_delete(self) -> None:
        """
        Lifecycle hook called after soft deletion.

        Override in subclasses to implement custom logic that should
        execute when an entity is soft deleted.
        """
        logger.debug(
            "Soft delete lifecycle hook - override in subclass for custom logic",
            entity_type=self.__class__.__name__
        )

    def _on_restore(self, deletion_info: dict[str, Any]) -> None:
        """
        Lifecycle hook called after restoration.

        Args:
            deletion_info: Information about the previous deletion

        Override in subclasses to implement custom logic that should
        execute when an entity is restored.
        """
        logger.debug(
            "Restore lifecycle hook - override in subclass for custom logic",
            entity_type=self.__class__.__name__,
            deletion_info=deletion_info
        )

    @classmethod
    def filter_active(cls, query: Query) -> Query:
        """
        Filter query to only include active (non-deleted) records.

        Args:
            query: SQLAlchemy query to filter

        Returns:
            Filtered query showing only active records
        """
        return query.filter(cls.deleted_at.is_(None))

    @classmethod
    def filter_deleted(cls, query: Query) -> Query:
        """
        Filter query to only include deleted records.

        Args:
            query: SQLAlchemy query to filter

        Returns:
            Filtered query showing only deleted records
        """
        return query.filter(cls.deleted_at.isnot(None))

    def get_deletion_age_seconds(self) -> float | None:
        """
        Get age of deletion in seconds.

        Returns:
            Seconds since deletion, or None if not deleted
        """
        if not self.is_deleted:
            return None
        return (_now_utc() - self.deleted_at).total_seconds()


class VersionedMixin:
    """
    Optimistic locking with comprehensive version tracking.
    
    Features:
    - Version number management
    - Optimistic lock conflict detection
    - Version update tracking with user and timestamp
    - Comprehensive version information
    """

    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="Optimistic locking version",
    )

    version_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of last version update",
    )

    version_updated_by: Mapped[UUID | None] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        comment="User who last updated version",
    )

    @declared_attr
    def __table_args__(self):
        """Add version-specific indexes."""
        existing = getattr(super(), "__table_args__", ()) or ()
        if isinstance(existing, dict):
            existing = (existing,)

        version_args = (
            # Index for version-based queries
            Index(f"ix_{self.__tablename__}_version", "id", "version"),
        )

        return existing + version_args

    def increment_version(self, updated_by: UUID | None = None) -> int:
        """
        Increment version for optimistic locking with tracking and concurrency safety.

        Safely increments the version number and updates tracking
        information for audit purposes.

        Args:
            updated_by: UUID of user updating the version

        Returns:
            New version number
        """
        old_version = self.version
        self.version += 1
        self.version_updated_at = _now_utc()
        self.version_updated_by = updated_by

        logger.debug(
            "Entity version incremented",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id) if hasattr(self, "id") else "unknown",
            old_version=old_version,
            new_version=self.version,
            updated_by=str(updated_by) if updated_by else None,
        )

        return self.version

    def check_version(self, expected_version: int) -> bool:
        """
        Check if current version matches expected version.

        Args:
            expected_version: Expected version number

        Returns:
            True if versions match, False otherwise
        """
        matches = self.version == expected_version

        if not matches:
            logger.warning(
                "Version mismatch detected",
                entity_type=self.__class__.__name__,
                entity_id=str(self.id) if hasattr(self, "id") else "unknown",
                expected_version=expected_version,
                actual_version=self.version,
            )

        return matches

    def validate_version_update(self, expected_version: int) -> None:
        """
        Validate version before update, raising exception on conflict.

        Args:
            expected_version: Expected version number

        Raises:
            OptimisticLockError: If version doesn't match expected
        """
        if not self.check_version(expected_version):
            raise OptimisticLockError(
                f"Version conflict: expected {expected_version}, "
                f"got {self.version} for {self.__class__.__name__}({self.id})"
            )

    def get_version_info(self) -> dict[str, Any]:
        """
        Get comprehensive version information.

        Returns:
            Dictionary with version details and metadata
        """
        return {
            "current_version": self.version,
            "version_updated_at": self.version_updated_at.isoformat()
            if self.version_updated_at
            else None,
            "version_updated_by": str(self.version_updated_by)
            if self.version_updated_by
            else None,
            "version_age_seconds": (
                (_now_utc() - self.version_updated_at).total_seconds()
                if self.version_updated_at
                else None
            ),
        }


class AuditMixin:
    """
    Comprehensive audit trail with user, network, and session tracking.
    
    Features:
    - Creation and update user tracking
    - IP address logging with validation
    - User agent tracking with size limits
    - Session ID tracking
    - Comprehensive audit summary generation
    """

    created_by: Mapped[UUID | None] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="User who created the entity",
    )

    updated_by: Mapped[UUID | None] = mapped_column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        comment="User who last updated the entity",
    )

    created_ip: Mapped[str | None] = mapped_column(
        String(45),  # Support IPv6 addresses
        nullable=True,
        comment="IP address of creator",
    )

    updated_ip: Mapped[str | None] = mapped_column(
        String(45), nullable=True, comment="IP address of last updater"
    )

    created_user_agent: Mapped[str | None] = mapped_column(
        String(500),  # Extended for modern user agents
        nullable=True,
        comment="User agent of creator",
    )

    updated_user_agent: Mapped[str | None] = mapped_column(
        String(500), nullable=True, comment="User agent of last updater"
    )

    created_session_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, comment="Session ID of creator"
    )

    updated_session_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, comment="Session ID of last updater"
    )

    @declared_attr
    def __table_args__(self):
        """Add audit-specific indexes."""
        existing = getattr(super(), "__table_args__", ()) or ()
        if isinstance(existing, dict):
            existing = (existing,)

        audit_args = (
            # Index for audit queries by user
            Index(f"ix_{self.__tablename__}_audit_created", "created_by", "created_at"),
            Index(f"ix_{self.__tablename__}_audit_updated", "updated_by", "updated_at"),
            # Index for IP-based security queries
            Index(f"ix_{self.__tablename__}_audit_ip", "created_ip", "updated_ip"),
        )

        return existing + audit_args

    def set_created_audit(
        self,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        additional_context: dict[str, Any] | None = None,
    ) -> None:
        """
        Set comprehensive creation audit information.

        Captures detailed context about entity creation including user,
        network, and session information for security and compliance.

        Args:
            user_id: UUID of creating user
            ip_address: IP address of creator
            user_agent: User agent string of creator
            session_id: Session ID of creator
            additional_context: Additional audit context
        """
        self.created_by = user_id
        self.created_ip = self._validate_ip_address(ip_address)
        self.created_user_agent = self._truncate_user_agent(user_agent)
        self.created_session_id = session_id

        logger.debug(
            "Creation audit context set",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id) if hasattr(self, "id") else "new",
            created_by=str(user_id) if user_id else None,
            created_ip=ip_address,
            has_user_agent=bool(user_agent),
            session_id=session_id,
        )

    def set_updated_audit(
        self,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        additional_context: dict[str, Any] | None = None,
    ) -> None:
        """
        Set comprehensive update audit information.

        Captures detailed context about entity updates for change tracking
        and compliance requirements.

        Args:
            user_id: UUID of updating user
            ip_address: IP address of updater
            user_agent: User agent string of updater
            session_id: Session ID of updater
            additional_context: Additional audit context
        """
        self.updated_by = user_id
        self.updated_ip = self._validate_ip_address(ip_address)
        self.updated_user_agent = self._truncate_user_agent(user_agent)
        self.updated_session_id = session_id

        logger.debug(
            "Update audit context set",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id) if hasattr(self, "id") else "unknown",
            updated_by=str(user_id) if user_id else None,
            updated_ip=ip_address,
            has_user_agent=bool(user_agent),
            session_id=session_id,
        )

    def _validate_ip_address(self, ip_address: str | None) -> str | None:
        """
        Validate and normalize IP address with proper validation.

        Args:
            ip_address: IP address to validate

        Returns:
            Validated IP address or None

        Raises:
            ValidationError: If IP address format is invalid
        """
        if not ip_address:
            return None

        # Strip whitespace
        ip_address = ip_address.strip()
        
        # Check length first
        if len(ip_address) > 45:  # Max IPv6 length
            logger.warning(
                "IP address too long, truncating",
                ip_address=ip_address[:50],  # Safe preview
            )
            ip_address = ip_address[:45]

        # Validate IP format
        try:
            # This will raise ValueError for invalid IPs
            ipaddress.ip_address(ip_address)
            return ip_address
        except ValueError as e:
            logger.warning(
                "Invalid IP address format",
                ip_address=ip_address[:50],  # Safe preview
                error=str(e)
            )
            # Return the original value for backwards compatibility
            # but log the validation failure
            return ip_address

    def _truncate_user_agent(self, user_agent: str | None) -> str | None:
        """
        Truncate user agent string to fit database constraints.

        Args:
            user_agent: User agent string to truncate

        Returns:
            Truncated user agent or None
        """
        if not user_agent:
            return None

        if len(user_agent) > 500:
            logger.debug(
                "User agent truncated for storage",
                original_length=len(user_agent),
                truncated_length=500,
            )
            return user_agent[:500]

        return user_agent

    def get_audit_summary(self) -> dict[str, Any]:
        """
        Get comprehensive audit summary for reporting.

        Returns:
            Dictionary with audit information and metadata
        """
        return {
            "created": {
                "by": str(self.created_by) if self.created_by else None,
                "at": self.created_at.isoformat()
                if hasattr(self, "created_at")
                else None,
                "ip": self.created_ip,
                "session": self.created_session_id,
                "user_agent": self.created_user_agent,
            },
            "updated": {
                "by": str(self.updated_by) if self.updated_by else None,
                "at": self.updated_at.isoformat()
                if hasattr(self, "updated_at")
                else None,
                "ip": self.updated_ip,
                "session": self.updated_session_id,
                "user_agent": self.updated_user_agent,
            },
        }


class MetadataMixin:
    """
    Flexible JSON metadata storage with nested key support and GIN indexing.
    
    Features:
    - Size-limited JSON storage with validation
    - Nested key access with dot notation
    - Deep merge capabilities for complex updates
    - Efficient GIN indexing for PostgreSQL
    - Comprehensive key management and introspection
    """

    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(
        EnhancedJSONType(max_size_kb=1024),  # 1MB limit for metadata
        nullable=True,
        default=dict,
        server_default="{}",
        comment="JSON metadata storage",
    )

    @declared_attr
    def __table_args__(self):
        """Add metadata-specific indexes."""
        existing = getattr(super(), "__table_args__", ()) or ()
        if isinstance(existing, dict):
            existing = (existing,)

        # Add GIN index for PostgreSQL JSON operations
        metadata_args = (
            Index(
                f"ix_{self.__tablename__}_metadata",
                "metadata_json",
                postgresql_using="gin",
            ),
        )

        return existing + metadata_args

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get metadata value with support for nested keys.

        Supports dot notation for nested access (e.g., "user.preferences.theme").

        Args:
            key: Metadata key (supports dot notation for nesting)
            default: Default value if key not found

        Returns:
            Metadata value or default
        """
        if self.metadata_json is None:
            return default

        # Handle nested keys with dot notation
        keys = key.split(".")
        value = self.metadata_json

        try:
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
        except (TypeError, KeyError):
            return default

    def set_metadata(self, key: str, value: Any, commit_immediately: bool = False) -> None:
        """
        Set metadata value with support for nested keys and defensive copying.

        Args:
            key: Metadata key (supports dot notation for nesting)
            value: Value to set
            commit_immediately: Whether to flush changes to DB immediately

        Raises:
            ValidationError: If key is invalid or value cannot be serialized
        """
        if not key or not isinstance(key, str):
            raise ValidationError("Metadata key must be a non-empty string")

        # Validate key format
        if '..' in key or key.startswith('.') or key.endswith('.'):
            raise ValidationError("Invalid metadata key format")

        if self.metadata_json is None:
            self.metadata_json = {}

        # Test serialization before setting
        try:
            json.dumps(value, default=str)
        except (TypeError, ValueError) as e:
            raise ValidationError(f"Value cannot be serialized to JSON: {e}")

        # Create defensive copy to avoid side effects
        if isinstance(value, dict | list):
            try:
                value = json.loads(json.dumps(value, default=str))
            except (TypeError, ValueError) as e:
                raise ValidationError(f"Failed to create defensive copy: {e}")

        # Handle nested keys with dot notation
        keys = key.split(".")
        current = self.metadata_json

        # Navigate to parent of target key
        for k in keys[:-1]:
            if not k:  # Empty key part
                raise ValidationError(f"Invalid metadata key format: '{key}'")
            
            if k not in current:
                current[k] = {}
            elif not isinstance(current[k], dict):
                raise ValidationError(
                    f"Cannot set nested key '{key}': '{k}' is not a dict"
                )
            current = current[k]

        # Validate final key
        final_key = keys[-1]
        if not final_key:
            raise ValidationError(f"Invalid metadata key format: '{key}'")

        # Set the final value
        current[final_key] = value

        # Mark as modified for SQLAlchemy
        self._mark_metadata_modified()

        # Optionally flush changes immediately
        if commit_immediately and hasattr(self, "_sa_instance_state") and self._sa_instance_state:
            try:
                from sqlalchemy.orm import object_session
                session = object_session(self)
                if session:
                    session.flush()
            except Exception as e:
                logger.warning(
                    "Failed to flush metadata changes",
                    entity_type=self.__class__.__name__,
                    entity_id=str(getattr(self, 'id', 'unknown')),
                    error=str(e)
                )

        logger.debug(
            "Metadata value set",
            entity_type=self.__class__.__name__,
            entity_id=str(getattr(self, 'id', 'unknown')),
            key=key,
            value_type=type(value).__name__,
            flushed=commit_immediately,
        )

    def update_metadata(self, data: dict[str, Any], merge_nested: bool = True) -> None:
        """
        Update multiple metadata values efficiently with deep merge support.

        Args:
            data: Dictionary of metadata to update
            merge_nested: Whether to merge nested dictionaries

        Raises:
            ValidationError: If data is invalid
        """
        if not isinstance(data, dict):
            raise ValidationError("Metadata update data must be a dictionary")

        if self.metadata_json is None:
            self.metadata_json = {}

        # Create defensive copy of data
        data = json.loads(json.dumps(data))

        if merge_nested:
            self._deep_merge_metadata(self.metadata_json, data)
        else:
            self.metadata_json.update(data)

        # Mark as modified for SQLAlchemy
        self._mark_metadata_modified()

        logger.debug(
            "Metadata bulk updated",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id) if hasattr(self, "id") else "unknown",
            keys_updated=list(data.keys()),
            merge_nested=merge_nested,
        )

    def _deep_merge_metadata(
        self, target: dict[str, Any], source: dict[str, Any]
    ) -> None:
        """
        Recursively merge metadata dictionaries with defensive copying.
        
        Args:
            target: Target dictionary to merge into
            source: Source dictionary to merge from
        """
        for key, value in source.items():
            if (
                key in target
                and isinstance(target[key], dict)
                and isinstance(value, dict)
            ):
                self._deep_merge_metadata(target[key], value)
            # Create defensive copy for complex objects
            elif isinstance(value, dict | list):
                target[key] = json.loads(json.dumps(value))
            else:
                target[key] = value

    def delete_metadata(self, key: str) -> bool:
        """
        Delete metadata key with support for nested keys.

        Args:
            key: Metadata key to delete (supports dot notation)

        Returns:
            True if key was deleted, False if not found
        """
        if not self.metadata_json:
            return False

        # Handle nested keys
        keys = key.split(".")
        current = self.metadata_json

        # Navigate to parent of target key
        try:
            for k in keys[:-1]:
                current = current[k]

            if keys[-1] in current:
                del current[keys[-1]]
                self._mark_metadata_modified()

                logger.debug(
                    "Metadata key deleted",
                    entity_type=self.__class__.__name__,
                    entity_id=str(self.id) if hasattr(self, "id") else "unknown",
                    key=key,
                )
                return True
        except (KeyError, TypeError):
            pass

        return False

    def has_metadata(self, key: str) -> bool:
        """
        Check if metadata key exists.

        Args:
            key: Metadata key to check (supports dot notation)

        Returns:
            True if key exists, False otherwise
        """
        return self.get_metadata(key, None) is not None

    def clear_metadata(self) -> None:
        """Clear all metadata."""
        self.metadata_json = {}
        self._mark_metadata_modified()

        logger.debug(
            "Metadata cleared",
            entity_type=self.__class__.__name__,
            entity_id=str(self.id) if hasattr(self, "id") else "unknown",
        )

    def _mark_metadata_modified(self) -> None:
        """Mark metadata as modified for SQLAlchemy change tracking."""
        if hasattr(self, "_sa_instance_state") and self._sa_instance_state:
            try:
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(self, "metadata_json")
            except Exception as e:
                logger.warning(
                    "Failed to mark metadata as modified",
                    entity_type=self.__class__.__name__,
                    error=str(e)
                )

    def get_metadata_keys(self, prefix: str = "") -> list[str]:
        """
        Get all metadata keys, optionally filtered by prefix.

        Args:
            prefix: Optional prefix to filter keys

        Returns:
            List of metadata keys
        """
        if not self.metadata_json:
            return []

        def collect_keys(obj: Any, current_path: str = "") -> list[str]:
            keys = []
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{current_path}.{key}" if current_path else key
                    if not prefix or full_key.startswith(prefix):
                        keys.append(full_key)
                    keys.extend(collect_keys(value, full_key))
            return keys

        return collect_keys(self.metadata_json)


# Composite model classes with multiple mixins


class AuditableModel(BaseModel, AuditMixin):
    """
    Model with comprehensive audit trail capabilities.

    Combines base model functionality with detailed audit tracking
    for applications requiring user action tracking and compliance.
    """

    __abstract__ = True


class SoftDeletableModel(BaseModel, SoftDeleteMixin):
    """
    Model with soft deletion capabilities.

    Provides non-destructive deletion for data retention and
    compliance requirements while maintaining query performance.
    """

    __abstract__ = True


class VersionedModel(BaseModel, VersionedMixin):
    """
    Model with optimistic locking version control.

    Provides concurrent modification protection with version
    tracking for high-concurrency applications.
    """

    __abstract__ = True


class FullAuditModel(
    BaseModel, AuditMixin, SoftDeleteMixin, VersionedMixin, MetadataMixin
):
    """
    Model with comprehensive audit, versioning, and metadata capabilities.

    Provides enterprise-grade data management with full audit trails,
    soft deletion, version control, and flexible metadata storage.

    Features:
    - Complete audit trail with user and session tracking
    - Soft deletion with restoration capabilities
    - Optimistic locking with version control
    - Flexible JSON metadata storage
    - Performance-optimized with intelligent indexing

    Usage Examples:
        class CriticalDocument(FullAuditModel):
            title: Mapped[str] = mapped_column(String(255))
            content: Mapped[str] = mapped_column(Text)

            def validate(self):
                super().validate()
                if not self.title.strip():
                    raise ModelValidationError("Title cannot be empty")
    """

    __abstract__ = True


# Enhanced bulk operation functions with explicit type hints


def bulk_soft_delete(
    session: Session,
    model_class: type[T],
    ids: list[UUID],
    deleted_by: UUID | None = None,
    reason: str | None = None,
    batch_size: int = 1000,
) -> int:
    """
    Perform bulk soft deletion with comprehensive tracking and batching.

    Efficiently soft deletes multiple records with performance optimization
    through batching and comprehensive audit logging.

    Args:
        session: SQLAlchemy session
        model_class: Model class to soft delete
        ids: List of UUIDs to soft delete
        deleted_by: UUID of user performing deletion
        reason: Reason for bulk deletion
        batch_size: Size of batches for large operations

    Returns:
        Number of records soft deleted

    Raises:
        SoftDeleteError: If bulk soft deletion fails
    """
    if not ids:
        return 0

    try:
        total_deleted = 0
        deletion_time = _now_utc()

        # Process in batches for performance
        for i in range(0, len(ids), batch_size):
            batch_ids = ids[i : i + batch_size]

            from sqlalchemy import update

            stmt = (
                update(model_class)
                .where(model_class.id.in_(batch_ids))
                .values(
                    deleted_at=deletion_time,
                    deleted_by=deleted_by,
                    deletion_reason=reason,
                )
            )

            result = session.execute(stmt)
            batch_deleted = result.rowcount
            total_deleted += batch_deleted

            logger.debug(
                "Bulk soft delete batch completed",
                model_class=model_class.__name__,
                batch_size=len(batch_ids),
                batch_deleted=batch_deleted,
                total_deleted=total_deleted,
            )

        logger.info(
            "Bulk soft deletion completed",
            model_class=model_class.__name__,
            total_ids=len(ids),
            total_deleted=total_deleted,
            deleted_by=str(deleted_by) if deleted_by else None,
            reason=reason,
        )

        return total_deleted

    except Exception as e:
        logger.exception(
            "Bulk soft deletion failed",
            model_class=model_class.__name__,
            ids_count=len(ids),
            error=str(e),
        )
        raise SoftDeleteError(f"Bulk soft deletion failed: {e}")


def bulk_restore(
    session: Session, model_class: type[T], ids: list[UUID], batch_size: int = 1000
) -> int:
    """
    Perform bulk restoration of soft deleted records.

    Efficiently restores multiple soft deleted records with
    performance optimization through batching.

    Args:
        session: SQLAlchemy session
        model_class: Model class to restore
        ids: List of UUIDs to restore
        batch_size: Size of batches for large operations

    Returns:
        Number of records restored

    Raises:
        SoftDeleteError: If bulk restoration fails
    """
    if not ids:
        return 0

    try:
        total_restored = 0

        # Process in batches for performance
        for i in range(0, len(ids), batch_size):
            batch_ids = ids[i : i + batch_size]

            from sqlalchemy import update

            stmt = (
                update(model_class)
                .where(model_class.id.in_(batch_ids))
                .where(
                    model_class.deleted_at.isnot(None)
                )  # Only restore deleted records
                .values(deleted_at=None, deleted_by=None, deletion_reason=None)
            )

            result = session.execute(stmt)
            batch_restored = result.rowcount
            total_restored += batch_restored

            logger.debug(
                "Bulk restore batch completed",
                model_class=model_class.__name__,
                batch_size=len(batch_ids),
                batch_restored=batch_restored,
                total_restored=total_restored,
            )

        logger.info(
            "Bulk restoration completed",
            model_class=model_class.__name__,
            total_ids=len(ids),
            total_restored=total_restored,
        )

        return total_restored

    except Exception as e:
        logger.exception(
            "Bulk restoration failed",
            model_class=model_class.__name__,
            ids_count=len(ids),
            error=str(e),
        )
        raise SoftDeleteError(f"Bulk restoration failed: {e}")


# Model lifecycle event handlers


@event.listens_for(BaseModel, "before_insert", propagate=True)
def before_insert_handler(mapper, connection, target):
    """Handle before insert events for all BaseModel instances with error handling."""
    try:
        # Ensure created_at is set if not already
        if hasattr(target, "created_at") and target.created_at is None:
            target.created_at = _now_utc()

        # Ensure updated_at is set for new records
        if hasattr(target, "updated_at") and target.updated_at is None:
            target.updated_at = _now_utc()

        # Initialize metadata if it's a MetadataMixin
        if hasattr(target, "metadata_json") and target.metadata_json is None:
            target.metadata_json = {}

        # Validate model before insert
        if hasattr(target, "validate"):
            target.validate()
            
    except Exception as e:
        logger.exception(
            "Before insert handler failed",
            model_class=target.__class__.__name__,
            error=str(e),
            error_type=type(e).__name__
        )
        raise


@event.listens_for(BaseModel, "before_update", propagate=True)
def before_update_handler(mapper, connection, target):
    """Handle before update events for all BaseModel instances with error handling."""
    try:
        # Ensure updated_at is set
        if hasattr(target, "updated_at"):
            target.updated_at = _now_utc()

        # Increment version if it's a VersionedMixin
        if hasattr(target, "version") and hasattr(target, "increment_version"):
            # Only increment if this is an actual update (not a new insert)
            if hasattr(target, "_sa_instance_state") and target._sa_instance_state.persistent:
                # Check if any non-timestamp fields have changed
                state = target._sa_instance_state
                if state.modified and any(
                    attr.key not in ['updated_at', 'version_updated_at'] 
                    for attr in state.modified
                ):
                    target.increment_version()

        # Validate model before update
        if hasattr(target, "validate"):
            target.validate()
            
    except Exception as e:
        logger.exception(
            "Before update handler failed",
            model_class=target.__class__.__name__,
            error=str(e),
            error_type=type(e).__name__
        )
        raise


# Enhanced performance monitoring decorator with async support
def monitor_query_performance(
    slow_query_threshold: float = 1.0,
    log_all_queries: bool = False
):
    """
    Decorator to monitor query performance with configurable thresholds.
    
    Tracks query duration and logs slow queries while supporting
    both synchronous and asynchronous operations.
    
    Args:
        slow_query_threshold: Duration in seconds to consider a query slow
        log_all_queries: Whether to log all queries regardless of duration
    
    Note: Unit tests should validate both sync and async decorator behavior
    explicitly to ensure proper metrics collection and error handling.
    """
    def decorator(func):
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            operation_name = f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Log based on configuration
                if duration > slow_query_threshold:
                    logger.warning(
                        "Slow query detected",
                        function=operation_name,
                        duration=duration,
                        threshold=slow_query_threshold,
                        args_count=len(args),
                        kwargs_keys=list(kwargs.keys()),
                    )
                elif log_all_queries:
                    logger.debug(
                        "Query completed",
                        function=operation_name,
                        duration=duration,
                    )

                # Record metrics safely
                try:
                    metrics.database_query_duration.labels(
                        operation=func.__name__
                    ).observe(duration)
                except Exception as metrics_error:
                    logger.debug(
                        "Failed to record query metrics",
                        error=str(metrics_error)
                    )

                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.exception(
                    "Query failed",
                    function=operation_name,
                    duration=duration,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                # Record error metrics safely
                try:
                    metrics.database_query_errors.labels(
                        operation=func.__name__, 
                        error_type=type(e).__name__
                    ).inc()
                except Exception as metrics_error:
                    logger.debug(
                        "Failed to record error metrics",
                        error=str(metrics_error)
                    )
                raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            operation_name = f"{func.__module__}.{func.__name__}"
            
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time

                # Log based on configuration
                if duration > slow_query_threshold:
                    logger.warning(
                        "Slow async query detected",
                        function=operation_name,
                        duration=duration,
                        threshold=slow_query_threshold,
                        args_count=len(args),
                        kwargs_keys=list(kwargs.keys()),
                    )
                elif log_all_queries:
                    logger.debug(
                        "Async query completed",
                        function=operation_name,
                        duration=duration,
                    )

                # Record metrics safely
                try:
                    metrics.database_query_duration.labels(
                        operation=func.__name__
                    ).observe(duration)
                except Exception as metrics_error:
                    logger.debug(
                        "Failed to record async query metrics",
                        error=str(metrics_error)
                    )

                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.exception(
                    "Async query failed",
                    function=operation_name,
                    duration=duration,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                # Record error metrics safely
                try:
                    metrics.database_query_errors.labels(
                        operation=func.__name__, 
                        error_type=type(e).__name__
                    ).inc()
                except Exception as metrics_error:
                    logger.debug(
                        "Failed to record async error metrics",
                        error=str(metrics_error)
                    )
                raise

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator
