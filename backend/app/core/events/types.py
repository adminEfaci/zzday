"""Event type definitions following pure Python principles.

This module provides comprehensive event type definitions for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are
completely independent of any framework (Pydantic, FastAPI, etc.).

The event system handles domain events, metadata management, and event serialization
with rich validation, type safety, and comprehensive error handling.

Design Principles:
- Pure Python classes with explicit validation
- Framework-agnostic design for maximum portability
- Comprehensive event metadata and tracing
- Rich error handling and recovery mechanisms
- Performance optimization with caching
- Security-focused event validation
- Type safety without framework dependencies
- Configurable serialization strategies

Architecture:
- EventMetadata: Event metadata with validation and tracing
- DomainEvent: Base domain event with lifecycle management
- EventValidator: Validation utilities for event data
- EventSerializer: Framework-agnostic serialization
- EventFactory: Event creation and reconstruction
"""

import json
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid4

from app.core.errors import ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)


# =====================================================================================
# ENUMS AND CONSTANTS
# =====================================================================================


class EventPriority(Enum):
    """Event priority levels for processing."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(Enum):
    """Event processing status."""

    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"


class SerializationFormat(Enum):
    """Event serialization formats."""

    JSON = "json"
    DICT = "dict"
    BINARY = "binary"


# =====================================================================================
# VALIDATION UTILITIES
# =====================================================================================


class EventValidator:
    """
    Event validation utilities following pure Python principles.

    Provides comprehensive validation methods for event data, metadata,
    and structure with clear error messages and type checking.

    Design Features:
    - Pure Python implementation
    - Comprehensive type validation
    - Clear error messages
    - Performance-optimized validation
    - Security-focused checks
    - Framework-independent validation
    """

    @staticmethod
    def validate_uuid(
        value: Any, field_name: str, required: bool = True
    ) -> UUID | None:
        """
        Validate UUID field with comprehensive checks.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required

        Returns:
            UUID: Validated UUID value

        Raises:
            ValidationError: If validation fails
        """
        if value is None:
            if required:
                raise ValidationError(f"{field_name} is required")
            return None

        if isinstance(value, UUID):
            return value

        if isinstance(value, str):
            try:
                return UUID(value)
            except ValueError:
                raise ValidationError(f"{field_name} must be a valid UUID")

        raise ValidationError(f"{field_name} must be a UUID or valid UUID string")

    @staticmethod
    def validate_string(
        value: Any,
        field_name: str,
        required: bool = True,
        min_length: int = 0,
        max_length: int | None = None,
        allowed_values: list[str] | None = None,
        pattern: str | None = None,
    ) -> str | None:
        """
        Validate string field with comprehensive checks.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            min_length: Minimum string length
            max_length: Maximum string length
            allowed_values: List of allowed values

        Returns:
            str: Validated string value

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required")
            return None

        if not isinstance(value, str):
            value = str(value)

        value = value.strip()

        if len(value) < min_length:
            raise ValidationError(
                f"{field_name} must be at least {min_length} characters"
            )

        if max_length and len(value) > max_length:
            raise ValidationError(
                f"{field_name} must be at most {max_length} characters"
            )

        if allowed_values and value not in allowed_values:
            raise ValidationError(
                f"{field_name} must be one of: {', '.join(allowed_values)}"
            )
        
        if pattern:
            import re
            if not re.match(pattern, value):
                raise ValidationError(
                    f"{field_name} does not match required pattern: {pattern}"
                )

        return value

    @staticmethod
    def validate_datetime(
        value: Any, field_name: str, required: bool = True
    ) -> datetime | None:
        """
        Validate datetime field with timezone handling.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required

        Returns:
            datetime: Validated datetime value

        Raises:
            ValidationError: If validation fails
        """
        if value is None:
            if required:
                raise ValidationError(f"{field_name} is required")
            return None

        if isinstance(value, datetime):
            # Ensure timezone awareness
            if value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            return value

        if isinstance(value, str):
            try:
                # Try parsing ISO format
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                return parsed
            except ValueError:
                raise ValidationError(
                    f"{field_name} must be a valid ISO datetime string"
                )

        if isinstance(value, int | float):
            try:
                return datetime.fromtimestamp(value, tz=UTC)
            except (ValueError, OSError):
                raise ValidationError(f"{field_name} timestamp is invalid")

        raise ValidationError(
            f"{field_name} must be a datetime, ISO string, or timestamp"
        )

    @staticmethod
    def validate_integer(
        value: Any,
        field_name: str,
        required: bool = True,
        min_value: int | None = None,
        max_value: int | None = None,
    ) -> int | None:
        """
        Validate integer field with range checks.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            int: Validated integer value

        Raises:
            ValidationError: If validation fails
        """
        if value is None:
            if required:
                raise ValidationError(f"{field_name} is required")
            return None

        try:
            value = int(value)
        except (ValueError, TypeError):
            raise ValidationError(f"{field_name} must be a valid integer")

        if min_value is not None and value < min_value:
            raise ValidationError(f"{field_name} must be at least {min_value}")

        if max_value is not None and value > max_value:
            raise ValidationError(f"{field_name} must be at most {max_value}")

        return value

    @staticmethod
    def validate_dict(
        value: Any,
        field_name: str,
        required: bool = True,
        allowed_keys: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Validate dictionary field with key validation.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            allowed_keys: List of allowed keys

        Returns:
            dict[str, Any]: Validated dictionary

        Raises:
            ValidationError: If validation fails
        """
        if value is None:
            if required:
                raise ValidationError(f"{field_name} is required")
            return None

        if not isinstance(value, dict):
            raise ValidationError(f"{field_name} must be a dictionary")

        if allowed_keys:
            invalid_keys = set(value.keys()) - set(allowed_keys)
            if invalid_keys:
                raise ValidationError(
                    f"{field_name} contains invalid keys: {', '.join(invalid_keys)}"
                )

        return value


# =====================================================================================
# EVENT METADATA
# =====================================================================================


@dataclass
class EventMetadata:
    """
    Event metadata for tracing, versioning, and correlation.

    Design Features:
    - Pure Python dataclass with explicit validation
    - Comprehensive event tracking and correlation
    - Performance optimization with caching
    - Security-focused validation
    - Framework-independent implementation

    Usage Example:
        metadata = EventMetadata(
            event_type="UserRegistered",
            aggregate_id=user_id,
            user_id=user_id,
            correlation_id="request-123"
        )

        # Validate metadata
        metadata.validate()

        # Serialize metadata
        data = metadata.to_dict()
    """

    # Core event identification
    event_id: UUID = field(default_factory=uuid4)
    event_type: str = field(default="")

    # Aggregate and domain information
    aggregate_id: UUID | None = field(default=None)
    aggregate_type: str | None = field(default=None)
    aggregate_version: int = field(default=1)

    # User and security context
    user_id: UUID | None = field(default=None)
    session_id: str | None = field(default=None)
    tenant_id: UUID | None = field(default=None)

    # Event correlation and causation
    correlation_id: str | None = field(default=None)
    causation_id: UUID | None = field(default=None)
    parent_event_id: UUID | None = field(default=None)

    # Timing and versioning
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    version: int = field(default=1)

    # Processing metadata
    priority: EventPriority = field(default=EventPriority.NORMAL)
    status: EventStatus = field(default=EventStatus.PENDING)
    retry_count: int = field(default=0)

    # Additional context
    source: str = field(default="")
    environment: str = field(default="")
    trace_id: str | None = field(default=None)
    span_id: str | None = field(default=None)

    def __post_init__(self):
        """Post-initialization validation and setup."""
        self.validate()

        # Set default source if not provided
        if not self.source:
            self.source = "ezzday-backend"

        # Generate correlation ID if not provided
        if not self.correlation_id:
            self.correlation_id = str(uuid4())

    def validate(self) -> None:
        """
        Validate event metadata fields.

        Raises:
            ValidationError: If validation fails
        """
        # Validate required fields
        self.event_id = EventValidator.validate_uuid(
            self.event_id, "event_id", required=True
        )
        self.event_type = EventValidator.validate_string(
            self.event_type, "event_type", required=True, min_length=1, max_length=100
        )

        # Validate optional UUIDs
        self.aggregate_id = EventValidator.validate_uuid(
            self.aggregate_id, "aggregate_id", required=False
        )
        self.user_id = EventValidator.validate_uuid(
            self.user_id, "user_id", required=False
        )
        self.causation_id = EventValidator.validate_uuid(
            self.causation_id, "causation_id", required=False
        )
        self.parent_event_id = EventValidator.validate_uuid(
            self.parent_event_id, "parent_event_id", required=False
        )
        self.tenant_id = EventValidator.validate_uuid(
            self.tenant_id, "tenant_id", required=False
        )

        # Validate strings
        self.aggregate_type = EventValidator.validate_string(
            self.aggregate_type, "aggregate_type", required=False, max_length=50
        )
        self.session_id = EventValidator.validate_string(
            self.session_id, "session_id", required=False, max_length=100
        )
        self.correlation_id = EventValidator.validate_string(
            self.correlation_id, "correlation_id", required=False, max_length=100
        )
        self.source = EventValidator.validate_string(
            self.source, "source", required=False, max_length=50
        )
        self.environment = EventValidator.validate_string(
            self.environment, "environment", required=False, max_length=20
        )

        # Validate datetime
        self.timestamp = EventValidator.validate_datetime(
            self.timestamp, "timestamp", required=True
        )

        # Validate integers
        self.version = EventValidator.validate_integer(
            self.version, "version", required=True, min_value=1, max_value=1000
        )
        self.aggregate_version = EventValidator.validate_integer(
            self.aggregate_version, "aggregate_version", required=True, min_value=1
        )
        self.retry_count = EventValidator.validate_integer(
            self.retry_count, "retry_count", required=True, min_value=0, max_value=100
        )

        # Validate enums
        if isinstance(self.priority, str):
            try:
                self.priority = EventPriority(self.priority)
            except ValueError:
                valid_priorities = [p.value for p in EventPriority]
                raise ValidationError(
                    f"priority must be one of: {', '.join(valid_priorities)}"
                )

        if isinstance(self.status, str):
            try:
                self.status = EventStatus(self.status)
            except ValueError:
                valid_statuses = [s.value for s in EventStatus]
                raise ValidationError(
                    f"status must be one of: {', '.join(valid_statuses)}"
                )

    def update_status(self, status: EventStatus) -> None:
        """Update event status with validation."""
        if not isinstance(status, EventStatus):
            raise ValidationError("status must be an EventStatus enum")
        self.status = status

    def increment_retry(self) -> None:
        """Increment retry count with bounds checking."""
        if self.retry_count >= 100:
            raise ValidationError("Maximum retry count exceeded")
        self.retry_count += 1

    def to_dict(self) -> dict[str, Any]:
        """
        Convert metadata to dictionary for serialization.

        Returns:
            dict[str, Any]: Serialized metadata
        """
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type,
            "aggregate_id": str(self.aggregate_id) if self.aggregate_id else None,
            "aggregate_type": self.aggregate_type,
            "aggregate_version": self.aggregate_version,
            "user_id": str(self.user_id) if self.user_id else None,
            "session_id": self.session_id,
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "correlation_id": self.correlation_id,
            "causation_id": str(self.causation_id) if self.causation_id else None,
            "parent_event_id": str(self.parent_event_id)
            if self.parent_event_id
            else None,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "priority": self.priority.value,
            "status": self.status.value,
            "retry_count": self.retry_count,
            "source": self.source,
            "environment": self.environment,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EventMetadata":
        """
        Create metadata from dictionary.

        Args:
            data: Dictionary data

        Returns:
            EventMetadata: Reconstructed metadata

        Raises:
            ValidationError: If data is invalid
        """
        try:
            # Convert string UUIDs back to UUID objects
            if "event_id" in data and isinstance(data["event_id"], str):
                data["event_id"] = UUID(data["event_id"])

            if data.get("aggregate_id"):
                data["aggregate_id"] = UUID(data["aggregate_id"])

            if data.get("user_id"):
                data["user_id"] = UUID(data["user_id"])

            if data.get("causation_id"):
                data["causation_id"] = UUID(data["causation_id"])

            if data.get("parent_event_id"):
                data["parent_event_id"] = UUID(data["parent_event_id"])

            if data.get("tenant_id"):
                data["tenant_id"] = UUID(data["tenant_id"])

            # Convert timestamp string back to datetime
            if "timestamp" in data and isinstance(data["timestamp"], str):
                data["timestamp"] = datetime.fromisoformat(
                    data["timestamp"].replace("Z", "+00:00")
                )

            # Convert enum strings back to enums
            if "priority" in data and isinstance(data["priority"], str):
                data["priority"] = EventPriority(data["priority"])

            if "status" in data and isinstance(data["status"], str):
                data["status"] = EventStatus(data["status"])

            return cls(**data)

        except Exception as e:
            logger.exception(
                "Failed to deserialize event metadata", error=str(e), data=data
            )
            raise ValidationError(f"Invalid event metadata: {e}")


# =====================================================================================
# DOMAIN EVENT BASE CLASS
# =====================================================================================


class DomainEvent(ABC):
    """
    Base domain event following pure Python principles.

    Provides framework-agnostic event handling with comprehensive metadata,
    validation, serialization, and lifecycle management.

    Design Features:
    - Pure Python implementation
    - Comprehensive event lifecycle management
    - Rich metadata and tracing support
    - Performance-optimized serialization
    - Security-focused validation
    - Framework-independent design

    Usage Example:
        class UserRegistered(DomainEvent):
            def __init__(self, user_id: UUID, email: str, **kwargs):
                super().__init__(**kwargs)
                self.user_id = user_id
                self.email = email

            def validate_payload(self) -> None:
                if not self.user_id:
                    raise ValidationError("user_id is required")
                if not self.email:
                    raise ValidationError("email is required")

        # Create event
        event = UserRegistered(
            user_id=UUID("..."),
            email="user@example.com",
            metadata=EventMetadata(aggregate_id=user_id)
        )

        # Serialize event
        data = event.to_dict()
    """

    def __init__(self, metadata: EventMetadata = None, **kwargs):
        """
        Initialize domain event.

        Args:
            metadata: Event metadata
            **kwargs: Additional event data
        """
        # Create metadata if not provided
        if metadata is None:
            metadata = EventMetadata(event_type=self.__class__.__name__)
        else:
            # Ensure event_type matches class name
            metadata.event_type = self.__class__.__name__

        self.metadata = metadata

        # Store additional data
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)

        # Validate event
        self.validate()

    @property
    def event_type(self) -> str:
        """Return the event type name."""
        return self.__class__.__name__

    @property
    def event_id(self) -> UUID:
        """Return the event ID."""
        return self.metadata.event_id

    @property
    def timestamp(self) -> datetime:
        """Return the event timestamp."""
        return self.metadata.timestamp

    @property
    def correlation_id(self) -> str | None:
        """Return the correlation ID."""
        return self.metadata.correlation_id

    def validate(self) -> None:
        """
        Validate complete event including metadata and payload.

        Raises:
            ValidationError: If validation fails
        """
        # Validate metadata
        self.metadata.validate()

        # Validate payload (implemented by subclasses)
        self.validate_payload()

    @abstractmethod
    def validate_payload(self) -> None:
        """
        Validate event-specific payload data.

        Must be implemented by subclasses to validate their specific data.

        Raises:
            ValidationError: If validation fails
        """

    def with_metadata(self, **kwargs) -> "DomainEvent":
        """
        Return a copy of the event with updated metadata.

        Args:
            **kwargs: Metadata fields to update

        Returns:
            DomainEvent: New event instance with updated metadata
        """
        # Create a copy of current metadata
        metadata_dict = self.metadata.to_dict()
        metadata_dict.update(kwargs)

        # Recreate metadata
        new_metadata = EventMetadata.from_dict(metadata_dict)

        # Create new event instance
        event_dict = self.to_dict()
        event_dict["metadata"] = new_metadata

        return self.__class__.from_dict(event_dict)

    def with_correlation(self, correlation_id: str) -> "DomainEvent":
        """
        Return a copy of the event with updated correlation ID.

        Args:
            correlation_id: New correlation ID

        Returns:
            DomainEvent: New event instance with updated correlation ID
        """
        return self.with_metadata(correlation_id=correlation_id)

    def with_causation(self, causation_id: UUID) -> "DomainEvent":
        """
        Return a copy of the event with updated causation ID.

        Args:
            causation_id: Causation event ID

        Returns:
            DomainEvent: New event instance with updated causation ID
        """
        return self.with_metadata(causation_id=causation_id)

    def to_dict(
        self, format: SerializationFormat = SerializationFormat.DICT
    ) -> dict[str, Any] | str | bytes:
        """
        Serialize event to specified format.

        Args:
            format: Serialization format

        Returns:
            Serialized event data

        Raises:
            ValidationError: If serialization fails
        """
        try:
            # Get base event data
            event_data = {}

            # Add all instance attributes except metadata
            for key, value in self.__dict__.items():
                if key != "metadata":
                    if isinstance(value, UUID):
                        event_data[key] = str(value)
                    elif isinstance(value, datetime):
                        event_data[key] = value.isoformat()
                    elif isinstance(value, Enum):
                        event_data[key] = value.value
                    else:
                        event_data[key] = value

            # Add metadata
            event_data["metadata"] = self.metadata.to_dict()

            # Add event type for reconstruction
            event_data["__event_type__"] = self.__class__.__name__

            if format == SerializationFormat.DICT:
                return event_data
            if format == SerializationFormat.JSON:
                return json.dumps(event_data, default=str, separators=(",", ":"))
            if format == SerializationFormat.BINARY:
                json_str = json.dumps(event_data, default=str, separators=(",", ":"))
                return json_str.encode("utf-8")
            raise ValidationError(f"Unsupported serialization format: {format}")

        except Exception as e:
            logger.exception(
                "Failed to serialize event",
                event_type=self.__class__.__name__,
                event_id=str(self.metadata.event_id),
                error=str(e),
            )
            raise ValidationError(f"Event serialization failed: {e}")

    @classmethod
    def from_dict(cls, data: dict[str, Any] | str | bytes) -> "DomainEvent":
        """
        Deserialize event from data.

        Args:
            data: Serialized event data

        Returns:
            DomainEvent: Reconstructed event

        Raises:
            ValidationError: If deserialization fails
        """
        try:
            # Handle different input formats
            if isinstance(data, bytes):
                data = data.decode("utf-8")

            if isinstance(data, str):
                data = json.loads(data)

            if not isinstance(data, dict):
                raise ValidationError("Event data must be a dictionary")

            # Extract metadata
            metadata_data = data.pop("metadata", {})
            metadata = EventMetadata.from_dict(metadata_data)

            # Remove event type marker
            data.pop("__event_type__", None)

            # Convert UUID strings back to UUIDs for known UUID fields
            uuid_fields = ["user_id", "aggregate_id", "tenant_id"]
            for field in uuid_fields:
                if data.get(field):
                    data[field] = UUID(data[field])

            # Convert datetime strings back to datetimes
            datetime_fields = ["created_at", "updated_at", "expires_at"]
            for field in datetime_fields:
                if data.get(field):
                    data[field] = datetime.fromisoformat(
                        data[field].replace("Z", "+00:00")
                    )

            # Create event instance
            return cls(metadata=metadata, **data)

        except Exception as e:
            logger.exception(
                "Failed to deserialize event",
                data_type=type(data).__name__,
                error=str(e),
            )
            raise ValidationError(f"Event deserialization failed: {e}")

    def get_size(self) -> int:
        """
        Get approximate event size in bytes.

        Returns:
            int: Event size in bytes
        """
        try:
            json_data = self.to_dict(SerializationFormat.JSON)
            return len(json_data.encode("utf-8"))
        except Exception:
            return 0
    
    def validate_size(self, max_size_bytes: int = 1024 * 1024) -> None:
        """
        Validate event size against maximum allowed size.
        
        Args:
            max_size_bytes: Maximum allowed size in bytes (default 1MB)
            
        Raises:
            ValidationError: If event exceeds maximum size
        """
        size = self.get_size()
        if size > max_size_bytes:
            raise ValidationError(
                f"Event size {size} bytes exceeds maximum allowed size {max_size_bytes} bytes"
            )

    def is_expired(self, ttl_seconds: int | None = None) -> bool:
        """
        Check if event has expired based on TTL.

        Args:
            ttl_seconds: Time to live in seconds

        Returns:
            bool: True if event is expired
        """
        if not ttl_seconds:
            return False

        age = (datetime.now(UTC) - self.metadata.timestamp).total_seconds()
        return age > ttl_seconds

    def __str__(self) -> str:
        """String representation of event."""
        return (
            f"{self.__class__.__name__}("
            f"event_id={self.metadata.event_id}, "
            f"timestamp={self.metadata.timestamp.isoformat()}"
            f")"
        )

    def __repr__(self) -> str:
        """Detailed representation of event."""
        return (
            f"{self.__class__.__name__}("
            f"event_id={self.metadata.event_id}, "
            f"event_type={self.metadata.event_type}, "
            f"aggregate_id={self.metadata.aggregate_id}, "
            f"timestamp={self.metadata.timestamp.isoformat()}, "
            f"correlation_id={self.metadata.correlation_id}"
            f")"
        )


# =====================================================================================
# EVENT FACTORY
# =====================================================================================


class EventFactory:
    """
    Factory for creating and reconstructing events.

    Provides centralized event creation, validation, and reconstruction
    with support for dynamic event type resolution and validation.
    """

    _event_types: dict[str, type[DomainEvent]] = {}

    @classmethod
    def register_event_type(cls, event_class: type[DomainEvent]) -> None:
        """
        Register an event class for dynamic reconstruction.

        Args:
            event_class: Event class to register
        """
        cls._event_types[event_class.__name__] = event_class
        logger.debug(f"Registered event type: {event_class.__name__}")

    @classmethod
    def create_event(
        cls, event_type: str, data: dict[str, Any], metadata: EventMetadata = None
    ) -> DomainEvent:
        """
        Create event instance from type name and data.

        Args:
            event_type: Event type name
            data: Event data
            metadata: Optional metadata

        Returns:
            DomainEvent: Created event instance

        Raises:
            ValidationError: If event creation fails
        """
        if event_type not in cls._event_types:
            available_types = list(cls._event_types.keys())
            raise ValidationError(
                f"Unknown event type: {event_type}. "
                f"Available types: {', '.join(available_types)}"
            )

        event_class = cls._event_types[event_type]

        try:
            event = event_class(metadata=metadata, **data)
            # Validate size for large events
            event.validate_size()
            return event
        except ValidationError:
            raise  # Re-raise validation errors as-is
        except Exception as e:
            logger.exception(
                "Failed to create event", 
                event_type=event_type, 
                error=str(e),
                data_keys=list(data.keys()) if data else [],
                metadata_present=metadata is not None
            )
            raise ValidationError(f"Failed to create {event_type}: {e}")

    @classmethod
    def reconstruct_event(cls, data: dict[str, Any] | str | bytes) -> DomainEvent:
        """
        Reconstruct event from serialized data.

        Args:
            data: Serialized event data

        Returns:
            DomainEvent: Reconstructed event

        Raises:
            ValidationError: If reconstruction fails
        """
        try:
            # Parse data if needed
            if isinstance(data, str | bytes):
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                data = json.loads(data)

            # Get event type
            event_type = data.get("__event_type__") or data.get("metadata", {}).get(
                "event_type"
            )

            if not event_type:
                raise ValidationError("Event type not found in data")

            if event_type not in cls._event_types:
                raise ValidationError(f"Unknown event type: {event_type}")

            event_class = cls._event_types[event_type]
            return event_class.from_dict(data)

        except Exception as e:
            logger.exception("Failed to reconstruct event", error=str(e))
            raise ValidationError(f"Event reconstruction failed: {e}")

    @classmethod
    def get_registered_types(cls) -> list[str]:
        """Get list of registered event types."""
        return list(cls._event_types.keys())


# =====================================================================================
# CONCRETE EVENT EXAMPLES
# =====================================================================================


class SystemEvent(DomainEvent):
    """Base class for system-level events."""

    def __init__(self, message: str = "", **kwargs):
        """Initialize system event."""
        super().__init__(**kwargs)
        self.message = message

    def validate_payload(self) -> None:
        """Validate system event payload."""
        self.message = EventValidator.validate_string(
            self.message, "message", required=False, max_length=500
        )


class ApplicationStarted(SystemEvent):
    """Event raised when application starts."""

    def __init__(self, version: str = "", **kwargs):
        """Initialize application started event."""
        super().__init__(**kwargs)
        self.version = version

    def validate_payload(self) -> None:
        """Validate application started payload."""
        super().validate_payload()
        self.version = EventValidator.validate_string(
            self.version, "version", required=False, max_length=20
        )


class ApplicationStopping(SystemEvent):
    """Event raised when application is stopping."""

    def __init__(self, reason: str = "", **kwargs):
        """Initialize application stopping event."""
        super().__init__(**kwargs)
        self.reason = reason

    def validate_payload(self) -> None:
        """Validate application stopping payload."""
        super().validate_payload()
        self.reason = EventValidator.validate_string(
            self.reason, "reason", required=False, max_length=200
        )


# Register system events
EventFactory.register_event_type(SystemEvent)
EventFactory.register_event_type(ApplicationStarted)
EventFactory.register_event_type(ApplicationStopping)


# =====================================================================================
# EVENT BUS INTERFACE
# =====================================================================================


@runtime_checkable
class IEventBus(Protocol):
    """
    Event bus interface protocol for dependency injection.

    Defines the contract that all event bus implementations must follow.
    This allows for proper dependency injection and interface-based programming.

    Design Features:
    - Protocol-based interface for type safety
    - Runtime checkable for validation
    - Minimal required interface for flexibility
    - Async-first design for scalability

    Usage:
        # Register implementation with DI container
        container.register(IEventBus, event_bus_instance)

        # Inject into services
        def __init__(self, event_bus: IEventBus):
            self.event_bus = event_bus
    """

    async def publish(
        self, event: DomainEvent, correlation_id: str | None = None
    ) -> None:
        """
        Publish a domain event.

        Args:
            event: The domain event to publish
            correlation_id: Optional correlation ID for request tracing

        Raises:
            RuntimeError: If bus is not started
            EventProcessingError: If event processing fails
            ValidationError: If event is invalid
        """
        ...

    def subscribe(
        self,
        event_type: type[DomainEvent],
        handler: Callable[[DomainEvent], None | Awaitable[None]],
    ) -> None:
        """
        Subscribe a handler to an event type.

        Args:
            event_type: The event class to listen for
            handler: Callable that processes the event (sync or async)

        Raises:
            ValidationError: If handler signature is invalid
        """
        ...

    def unsubscribe(
        self,
        event_type: type[DomainEvent],
        handler: Callable[[DomainEvent], None | Awaitable[None]],
    ) -> None:
        """
        Remove a handler subscription for an event type.

        Args:
            event_type: The event class to stop listening for
            handler: The handler to remove
        """
        ...

    async def start(self) -> None:
        """
        Initialize the event bus and prepare for event processing.

        Raises:
            EventBusError: If initialization fails
        """
        ...

    async def stop(self) -> None:
        """
        Gracefully shutdown the event bus and cleanup resources.

        Should not raise exceptions - must cleanup regardless of state.
        """
        ...


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "ApplicationStarted",
    "ApplicationStopping",
    "DomainEvent",
    "EventFactory",
    # Core classes
    "EventMetadata",
    # Enums
    "EventPriority",
    "EventStatus",
    "EventValidator",
    # Event bus interface
    "IEventBus",
    "SerializationFormat",
    # System events
    "SystemEvent",
]
