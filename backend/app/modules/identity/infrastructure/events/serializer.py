"""
Event Serializer Implementation

Handles serialization and deserialization of domain events to/from various formats
including JSON, binary, and compressed formats with schema validation and versioning.
"""

import gzip
import json
import pickle
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

logger = get_logger(__name__)


class SerializationFormat(Enum):
    """Supported serialization formats."""
    
    JSON = "json"
    COMPRESSED_JSON = "compressed_json"
    BINARY = "binary"
    PICKLE = "pickle"  # For internal use only


class SerializationError(Exception):
    """Exception raised during serialization/deserialization."""


class EventSerializer:
    """
    Event serializer for identity domain events.
    
    Provides comprehensive serialization and deserialization capabilities
    with support for multiple formats, schema validation, versioning,
    and performance optimization.
    
    Features:
    - Multiple serialization formats (JSON, binary, compressed)
    - Schema validation and versioning
    - Custom type handling (UUID, datetime, enums)
    - Compression for large events
    - Performance optimization with caching
    - Error handling and recovery
    - Metadata preservation
    
    Usage:
        # Initialize serializer
        serializer = EventSerializer()
        
        # Serialize event
        serialized_data = serializer.serialize(event, format=SerializationFormat.JSON)
        
        # Deserialize event
        event = serializer.deserialize(serialized_data, UserCreated)
        
        # Bulk operations
        events = [event1, event2, event3]
        serialized_batch = serializer.serialize_batch(events)
        deserialized_events = serializer.deserialize_batch(serialized_batch)
    """
    
    def __init__(
        self,
        compression_threshold: int = 1024,  # Compress events larger than 1KB
        enable_schema_validation: bool = True,
        enable_type_checking: bool = True,
        preserve_original_format: bool = True,
    ):
        """
        Initialize event serializer.
        
        Args:
            compression_threshold: Size threshold for automatic compression
            enable_schema_validation: Enable schema validation
            enable_type_checking: Enable strict type checking
            preserve_original_format: Preserve original serialization format info
        """
        self._compression_threshold = compression_threshold
        self._enable_schema_validation = enable_schema_validation
        self._enable_type_checking = enable_type_checking
        self._preserve_original_format = preserve_original_format
        
        # Type converters for special types
        self._type_converters = {
            UUID: lambda x: str(x),
            datetime: lambda x: x.isoformat() if x else None,
        }
        
        # Type reconstructors
        self._type_reconstructors = {
            'UUID': lambda x: UUID(x) if x else None,
            'datetime': self._parse_datetime,
        }
        
        # Statistics
        self._stats = {
            "serialized_events": 0,
            "deserialized_events": 0,
            "compression_saves": 0,
            "serialization_errors": 0,
            "deserialization_errors": 0,
        }
        
        logger.info(
            "EventSerializer initialized",
            compression_threshold=compression_threshold,
            schema_validation=enable_schema_validation,
        )
    
    def _raise_unsupported_format(self, format_value: str) -> None:
        """Raise SerializationError for unsupported format."""
        raise SerializationError(f"Unsupported serialization format: {format_value}")
    
    def _raise_invalid_batch_format(self) -> None:
        """Raise SerializationError for invalid batch format."""
        raise SerializationError("Invalid batch format: missing 'events' field")
    
    def serialize(
        self,
        event: IdentityDomainEvent,
        serialization_format: SerializationFormat = SerializationFormat.JSON,
        include_metadata: bool = True,
    ) -> str | bytes:
        """
        Serialize a domain event to the specified format.
        
        Args:
            event: Event to serialize
            serialization_format: Target serialization format
            include_metadata: Include serialization metadata
            
        Returns:
            Serialized event data
            
        Raises:
            SerializationError: If serialization fails
        """
        try:
            # Convert event to dictionary
            event_dict = self._event_to_dict(event)
            
            # Add serialization metadata
            if include_metadata:
                event_dict["__serialization_metadata__"] = {
                    "format": serialization_format.value,
                    "version": "1.0",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "event_type": event.__class__.__name__,
                    "serializer": "EventSerializer",
                }
            
            # Serialize based on format
            if serialization_format == SerializationFormat.JSON:
                return self._serialize_json(event_dict)
            if serialization_format == SerializationFormat.COMPRESSED_JSON:
                return self._serialize_compressed_json(event_dict)
            if serialization_format == SerializationFormat.BINARY:
                return self._serialize_binary(event_dict)
            if serialization_format == SerializationFormat.PICKLE:
                return self._serialize_pickle(event)
            self._raise_unsupported_format(serialization_format.value)
            
        except Exception as e:
            self._stats["serialization_errors"] += 1
            logger.exception(
                "Event serialization failed",
                event_type=event.__class__.__name__,
                event_id=str(getattr(event, 'event_id', 'unknown')),
                format=serialization_format.value,
                error=str(e),
            )
            raise SerializationError(f"Failed to serialize event: {e}") from e
        finally:
            self._stats["serialized_events"] += 1
    
    def deserialize(
        self,
        data: str | bytes,
        event_type: type[IdentityDomainEvent] | None = None,
    ) -> IdentityDomainEvent:
        """
        Deserialize data to a domain event.
        
        Args:
            data: Serialized event data
            event_type: Expected event type (for validation)
            
        Returns:
            Deserialized domain event
            
        Raises:
            SerializationError: If deserialization fails
        """
        try:
            # Detect format and deserialize
            event_dict = self._detect_and_deserialize(data)
            
            # Validate schema if enabled
            if self._enable_schema_validation:
                self._validate_event_schema(event_dict)
            
            # Extract serialization metadata
            serialization_metadata = event_dict.pop("__serialization_metadata__", {})
            
            # Reconstruct event object
            event = self._dict_to_event(event_dict, event_type)
            
            # Store original serialization metadata if requested
            if self._preserve_original_format and serialization_metadata:
                event._original_serialization_metadata = serialization_metadata
            
            self._stats["deserialized_events"] += 1
            
            logger.debug(
                "Event deserialized successfully",
                event_type=event.__class__.__name__,
                event_id=str(getattr(event, 'event_id', 'unknown')),
                original_format=serialization_metadata.get('format', 'unknown'),
            )
            
            return event
            
        except Exception as e:
            self._stats["deserialization_errors"] += 1
            logger.exception(
                "Event deserialization failed",
                data_type=type(data).__name__,
                data_size=len(data) if hasattr(data, '__len__') else 'unknown',
                error=str(e),
            )
            raise SerializationError(f"Failed to deserialize event: {e}") from e
    
    def serialize_batch(
        self,
        events: list[IdentityDomainEvent],
        format: SerializationFormat = SerializationFormat.JSON,
    ) -> str | bytes:
        """
        Serialize multiple events as a batch.
        
        Args:
            events: List of events to serialize
            format: Target serialization format
            
        Returns:
            Serialized batch data
        """
        try:
            batch_dict = {
                "events": [self._event_to_dict(event) for event in events],
                "batch_metadata": {
                    "count": len(events),
                    "format": format.value,
                    "version": "1.0",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "serializer": "EventSerializer",
                },
            }
            
            # Serialize based on format
            if format == SerializationFormat.JSON:
                return self._serialize_json(batch_dict)
            if format == SerializationFormat.COMPRESSED_JSON:
                return self._serialize_compressed_json(batch_dict)
            if format == SerializationFormat.BINARY:
                return self._serialize_binary(batch_dict)
            raise SerializationError(f"Batch serialization not supported for format: {format}")
                
        except Exception as e:
            logger.exception(
                "Batch serialization failed",
                event_count=len(events),
                format=format.value,
                error=str(e),
            )
            raise SerializationError(f"Failed to serialize event batch: {e}") from e
    
    def deserialize_batch(
        self,
        data: str | bytes,
    ) -> list[IdentityDomainEvent]:
        """
        Deserialize batch data to multiple events.
        
        Args:
            data: Serialized batch data
            
        Returns:
            List of deserialized events
        """
        try:
            # Detect format and deserialize
            batch_dict = self._detect_and_deserialize(data)
            
            # Validate batch structure
            if "events" not in batch_dict:
                raise SerializationError("Invalid batch format: missing 'events' field")
            
            batch_metadata = batch_dict.get("batch_metadata", {})
            events_data = batch_dict["events"]
            
            # Deserialize each event
            events = []
            for event_dict in events_data:
                event = self._dict_to_event(event_dict)
                events.append(event)
            
            logger.debug(
                "Batch deserialized successfully",
                event_count=len(events),
                original_format=batch_metadata.get('format', 'unknown'),
            )
            
            return events
            
        except Exception as e:
            logger.exception(
                "Batch deserialization failed",
                data_type=type(data).__name__,
                error=str(e),
            )
            raise SerializationError(f"Failed to deserialize event batch: {e}") from e
    
    def _event_to_dict(self, event: IdentityDomainEvent) -> dict[str, Any]:
        """Convert event to dictionary with type information."""
        result = {
            "__event_type__": event.__class__.__name__,
            "__event_module__": event.__class__.__module__,
        }
        
        # Convert event attributes
        for key, value in event.__dict__.items():
            if key.startswith('_'):
                continue  # Skip private attributes
            
            result[key] = self._convert_value(value)
        
        # Add metadata if present
        if hasattr(event, 'get_event_metadata'):
            result["__event_metadata__"] = event.get_event_metadata()
        
        return result
    
    def _dict_to_event(
        self,
        event_dict: dict[str, Any],
        expected_type: type[IdentityDomainEvent] | None = None,
    ) -> IdentityDomainEvent:
        """Convert dictionary to event object."""
        # Get event type information
        event_type_name = event_dict.pop("__event_type__", None)
        event_module = event_dict.pop("__event_module__", None)
        event_dict.pop("__event_metadata__", {})
        
        if not event_type_name:
            raise SerializationError("Missing event type information")
        
        # Validate expected type if provided
        if expected_type and event_type_name != expected_type.__name__:
            raise SerializationError(
                f"Event type mismatch: expected {expected_type.__name__}, got {event_type_name}"
            )
        
        # Import and get event class
        event_class = self._get_event_class(event_type_name, event_module)
        
        # Reconstruct values
        reconstructed_dict = {}
        for key, value in event_dict.items():
            reconstructed_dict[key] = self._reconstruct_value(value)
        
        # Create event instance
        try:
            # Try to create with all attributes
            event = event_class(**reconstructed_dict)
        except TypeError as e:
            # Fallback: create with minimal attributes and set others manually
            logger.debug(
                "Using fallback event creation",
                event_type=event_type_name,
                error=str(e),
            )
            event = event_class()
            for key, value in reconstructed_dict.items():
                setattr(event, key, value)
        
        return event
    
    def _convert_value(self, value: Any) -> Any:
        """Convert a value to a serializable format."""
        if value is None:
            return None
        if isinstance(value, str | int | float | bool):
            return value
        if isinstance(value, list | tuple):
            return [self._convert_value(item) for item in value]
        if isinstance(value, dict):
            return {k: self._convert_value(v) for k, v in value.items()}
        if isinstance(value, Enum):
            return {"__type__": "Enum", "__value__": value.value, "__class__": value.__class__.__name__}
        if isinstance(value, UUID):
            return {"__type__": "UUID", "__value__": str(value)}
        if isinstance(value, datetime):
            return {"__type__": "datetime", "__value__": value.isoformat()}
        if is_dataclass(value):
            return {"__type__": "dataclass", "__value__": asdict(value), "__class__": value.__class__.__name__}
        # Try to convert using registered converters
        for type_class, converter in self._type_converters.items():
            if isinstance(value, type_class):
                return {"__type__": type_class.__name__, "__value__": converter(value)}

        # Fallback to string representation
        logger.warning(
            "Converting unknown type to string",
            value_type=type(value).__name__,
            value=str(value),
        )
        return {"__type__": "string", "__value__": str(value)}
    
    def _reconstruct_value(self, value: Any) -> Any:
        """Reconstruct a value from serialized format."""
        if not isinstance(value, dict) or "__type__" not in value:
            if isinstance(value, list):
                return [self._reconstruct_value(item) for item in value]
            if isinstance(value, dict):
                return {k: self._reconstruct_value(v) for k, v in value.items()}
            return value
        
        type_name = value["__type__"]
        type_value = value["__value__"]
        
        if type_name == "UUID":
            return UUID(type_value) if type_value else None
        if type_name == "datetime":
            return self._parse_datetime(type_value)
        if type_name == "Enum":
            # Note: Enum reconstruction needs the actual enum class
            return type_value  # Return raw value for now
        if type_name in self._type_reconstructors:
            return self._type_reconstructors[type_name](type_value)
        logger.warning(
            "Unknown type during reconstruction",
            type_name=type_name,
            value=type_value,
        )
        return type_value
    
    def _get_event_class(self, event_type_name: str, event_module: str | None = None) -> type[IdentityDomainEvent]:
        """Get event class by name and optional module."""
        # Try to import from the event module
        if event_module:
            try:
                module = __import__(event_module, fromlist=[event_type_name])
                return getattr(module, event_type_name)
            except (ImportError, AttributeError) as e:
                logger.debug(
                    "Failed to import from specified module",
                    event_type=event_type_name,
                    module=event_module,
                    error=str(e),
                )
        
        # Try to import from known event modules
        event_modules = [
            "app.modules.identity.domain.entities.user.user_events",
            "app.modules.identity.domain.entities.session.session_events", 
            "app.modules.identity.domain.entities.group.group_events",
            "app.modules.identity.domain.entities.role.role_events",
            "app.modules.identity.domain.entities.admin.admin_events",
        ]
        
        for module_name in event_modules:
            try:
                module = __import__(module_name, fromlist=[event_type_name])
                if hasattr(module, event_type_name):
                    return getattr(module, event_type_name)
            except ImportError:
                continue
        
        raise SerializationError(
            f"Cannot find event class: {event_type_name} in module: {event_module}"
        )
    
    def _serialize_json(self, data: dict[str, Any]) -> str:
        """Serialize to JSON format."""
        return json.dumps(data, separators=(',', ':'), ensure_ascii=False)
    
    def _serialize_compressed_json(self, data: dict[str, Any]) -> bytes:
        """Serialize to compressed JSON format."""
        json_str = self._serialize_json(data)
        json_bytes = json_str.encode('utf-8')
        
        # Only compress if above threshold
        if len(json_bytes) > self._compression_threshold:
            compressed = gzip.compress(json_bytes)
            if len(compressed) < len(json_bytes):
                self._stats["compression_saves"] += 1
                return compressed
        
        return json_bytes
    
    def _serialize_binary(self, data: dict[str, Any]) -> bytes:
        """Serialize to binary format."""
        json_str = self._serialize_json(data)
        return json_str.encode('utf-8')
    
    def _serialize_pickle(self, event: IdentityDomainEvent) -> bytes:
        """Serialize using pickle (internal use only)."""
        return pickle.dumps(event)
    
    def _detect_and_deserialize(self, data: str | bytes) -> dict[str, Any]:
        """Detect format and deserialize data."""
        if isinstance(data, str):
            # JSON format
            return json.loads(data)
        if isinstance(data, bytes):
            # Try compressed JSON first
            try:
                decompressed = gzip.decompress(data)
                return json.loads(decompressed.decode('utf-8'))
            except (gzip.BadGzipFile, OSError):
                # Try regular JSON
                try:
                    return json.loads(data.decode('utf-8'))
                except UnicodeDecodeError:
                    # Try pickle as last resort
                    return pickle.loads(data)
        else:
            raise SerializationError(f"Unsupported data type: {type(data)}")
    
    def _validate_event_schema(self, event_dict: dict[str, Any]) -> None:
        """Validate event schema."""
        if not self._enable_schema_validation:
            return
        
        # Check required fields
        required_fields = ["__event_type__"]
        for field in required_fields:
            if field not in event_dict:
                raise SerializationError(f"Missing required field: {field}")
        
        # Additional validation can be added here
    
    def _parse_datetime(self, dt_str: str) -> datetime | None:
        """Parse datetime string with timezone support."""
        if not dt_str:
            return None
        
        try:
            # Handle timezone info
            if dt_str.endswith('Z'):
                dt_str = dt_str[:-1] + '+00:00'
            
            return datetime.fromisoformat(dt_str)
        except ValueError as e:
            logger.warning(
                "Failed to parse datetime",
                datetime_string=dt_str,
                error=str(e),
            )
            return None
    
    def get_statistics(self) -> dict[str, Any]:
        """Get serializer statistics."""
        return {
            "compression_threshold": self._compression_threshold,
            "schema_validation_enabled": self._enable_schema_validation,
            "type_checking_enabled": self._enable_type_checking,
            **self._stats,
        }
    
    def reset_statistics(self) -> None:
        """Reset serializer statistics."""
        self._stats = {
            "serialized_events": 0,
            "deserialized_events": 0,
            "compression_saves": 0,
            "serialization_errors": 0,
            "deserialization_errors": 0,
        }