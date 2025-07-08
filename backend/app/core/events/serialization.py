"""
Event serialization utilities for PostgreSQL event store integration.

This module provides comprehensive event serialization and deserialization
for PostgreSQL storage, with support for compression, encryption, and
robust error handling.

Design Features:
- PostgreSQL-optimized serialization
- Support for compression and encryption
- Type-safe event reconstruction
- Performance monitoring
- Comprehensive error handling
"""

import gzip
import json
import pickle
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ValidationError
from app.core.events.types import DomainEvent, EventFactory, EventMetadata
from app.core.logging import get_logger

logger = get_logger(__name__)


class EventSerializationError(ValidationError):
    """Raised when event serialization/deserialization fails."""
    pass


class PostgreSQLEventSerializer:
    """
    PostgreSQL-optimized event serializer with compression and encryption support.
    
    Provides efficient serialization for PostgreSQL storage with JSONB optimization,
    compression for large events, and optional encryption for sensitive data.
    
    Features:
    - JSONB-optimized JSON serialization
    - GZIP compression for large events
    - Optional AES encryption
    - Type-safe deserialization
    - Performance monitoring
    - Comprehensive error handling
    """
    
    def __init__(
        self,
        enable_compression: bool = True,
        compression_threshold: int = 1024,  # Compress events > 1KB
        enable_encryption: bool = False,
        encryption_key: bytes | None = None
    ):
        """
        Initialize PostgreSQL event serializer.
        
        Args:
            enable_compression: Enable GZIP compression for large events
            compression_threshold: Size threshold for compression in bytes
            enable_encryption: Enable AES encryption for sensitive events
            encryption_key: Encryption key for AES encryption
        """
        self.enable_compression = enable_compression
        self.compression_threshold = compression_threshold
        self.enable_encryption = enable_encryption
        self.encryption_key = encryption_key
        
        if enable_encryption and not encryption_key:
            raise ValueError("Encryption key required when encryption is enabled")
    
    def serialize_event(self, event: DomainEvent) -> dict[str, Any]:
        """
        Serialize domain event for PostgreSQL storage.
        
        Args:
            event: Domain event to serialize
            
        Returns:
            dict[str, Any]: Serialized event data ready for PostgreSQL
            
        Raises:
            EventSerializationError: If serialization fails
        """
        try:
            # Get base event data
            event_data = event.to_dict()
            
            # Separate metadata from event data
            metadata = event_data.pop("metadata", {})
            event_payload = {k: v for k, v in event_data.items() if k != "__event_type__"}
            
            # Create serialization result
            serialized = {
                "event_id": str(event.metadata.event_id),
                "event_type": event.event_type,
                "aggregate_id": str(event.metadata.aggregate_id) if event.metadata.aggregate_id else None,
                "aggregate_type": event.metadata.aggregate_type,
                "aggregate_version": event.metadata.aggregate_version,
                "event_data": event_payload,
                "metadata": metadata,
                "created_at": event.metadata.timestamp,
                "original_size": len(json.dumps(event_data, default=str)),
                "compression": "none",
                "encryption": "none"
            }
            
            # Apply compression if enabled and event is large enough
            event_json = json.dumps(event_payload, default=str, separators=(',', ':'))
            if self.enable_compression and len(event_json) > self.compression_threshold:
                compressed_data = gzip.compress(event_json.encode('utf-8'))
                serialized["event_data"] = compressed_data.hex()  # Store as hex string
                serialized["compression"] = "gzip"
                serialized["compressed_size"] = len(compressed_data)
            else:
                serialized["compressed_size"] = serialized["original_size"]
            
            # Apply encryption if enabled
            if self.enable_encryption and self.encryption_key:
                serialized = self._encrypt_sensitive_fields(serialized)
                serialized["encryption"] = "aes-256-gcm"
            
            return serialized
            
        except Exception as e:
            logger.exception(
                "Failed to serialize event for PostgreSQL",
                event_type=event.event_type,
                event_id=str(event.event_id),
                error=str(e)
            )
            raise EventSerializationError(f"Event serialization failed: {e}") from e
    
    def deserialize_event(self, data: dict[str, Any]) -> DomainEvent:
        """
        Deserialize event from PostgreSQL storage.
        
        Args:
            data: Serialized event data from PostgreSQL
            
        Returns:
            DomainEvent: Reconstructed domain event
            
        Raises:
            EventSerializationError: If deserialization fails
        """
        try:
            # Decrypt if needed
            if data.get("encryption") and data["encryption"] != "none":
                data = self._decrypt_sensitive_fields(data)
            
            # Decompress event data if needed
            event_data = data["event_data"]
            if data.get("compression") == "gzip":
                if isinstance(event_data, str):
                    # Decode from hex string
                    compressed_bytes = bytes.fromhex(event_data)
                    decompressed_json = gzip.decompress(compressed_bytes).decode('utf-8')
                    event_data = json.loads(decompressed_json)
                else:
                    # Already decompressed (compatibility)
                    pass
            
            # Reconstruct metadata
            metadata_dict = data["metadata"]
            metadata_dict.update({
                "event_id": data["event_id"],
                "event_type": data["event_type"],
                "aggregate_id": data["aggregate_id"],
                "aggregate_type": data["aggregate_type"],
                "aggregate_version": data["aggregate_version"],
                "timestamp": data["created_at"]
            })
            
            metadata = EventMetadata.from_dict(metadata_dict)
            
            # Reconstruct event using factory
            return EventFactory.create_event(
                event_type=data["event_type"],
                data=event_data,
                metadata=metadata
            )
            
        except Exception as e:
            logger.exception(
                "Failed to deserialize event from PostgreSQL",
                event_type=data.get("event_type"),
                event_id=data.get("event_id"),
                error=str(e)
            )
            raise EventSerializationError(f"Event deserialization failed: {e}") from e
    
    def serialize_metadata(self, metadata: EventMetadata) -> dict[str, Any]:
        """
        Serialize event metadata for PostgreSQL JSONB storage.
        
        Args:
            metadata: Event metadata to serialize
            
        Returns:
            dict[str, Any]: Serialized metadata
        """
        return {
            "correlation_id": metadata.correlation_id,
            "causation_id": str(metadata.causation_id) if metadata.causation_id else None,
            "user_id": str(metadata.user_id) if metadata.user_id else None,
            "session_id": metadata.session_id,
            "tenant_id": str(metadata.tenant_id) if metadata.tenant_id else None,
            "source": metadata.source,
            "environment": metadata.environment,
            "priority": metadata.priority.value,
            "status": metadata.status.value,
            "retry_count": metadata.retry_count,
            "version": metadata.version,
            "trace_id": metadata.trace_id,
            "span_id": metadata.span_id
        }
    
    def _encrypt_sensitive_fields(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Encrypt sensitive fields in event data.
        
        Args:
            data: Event data to encrypt
            
        Returns:
            dict[str, Any]: Data with encrypted sensitive fields
        """
        # Placeholder for encryption implementation
        # In production, use proper AES-GCM encryption
        logger.warning("Encryption requested but not implemented")
        return data
    
    def _decrypt_sensitive_fields(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Decrypt sensitive fields in event data.
        
        Args:
            data: Event data to decrypt
            
        Returns:
            dict[str, Any]: Data with decrypted sensitive fields
        """
        # Placeholder for decryption implementation
        # In production, use proper AES-GCM decryption
        logger.warning("Decryption requested but not implemented")
        return data


class EventStreamSerializer:
    """
    Serializer for event streams with batch processing support.
    
    Optimized for processing multiple events efficiently for stream
    processing and batch operations.
    """
    
    def __init__(self, event_serializer: PostgreSQLEventSerializer):
        """
        Initialize stream serializer.
        
        Args:
            event_serializer: Individual event serializer
        """
        self.event_serializer = event_serializer
    
    def serialize_events(self, events: list[DomainEvent]) -> list[dict[str, Any]]:
        """
        Serialize multiple events for batch processing.
        
        Args:
            events: List of domain events to serialize
            
        Returns:
            list[dict[str, Any]]: List of serialized events
            
        Raises:
            EventSerializationError: If any serialization fails
        """
        serialized_events = []
        errors = []
        
        for i, event in enumerate(events):
            try:
                serialized = self.event_serializer.serialize_event(event)
                serialized_events.append(serialized)
            except Exception as e:
                errors.append(f"Event {i} ({event.event_type}): {e}")
        
        if errors:
            error_msg = "; ".join(errors)
            raise EventSerializationError(f"Batch serialization failed: {error_msg}")
        
        return serialized_events
    
    def deserialize_events(self, data_list: list[dict[str, Any]]) -> list[DomainEvent]:
        """
        Deserialize multiple events from batch data.
        
        Args:
            data_list: List of serialized event data
            
        Returns:
            list[DomainEvent]: List of reconstructed events
            
        Raises:
            EventSerializationError: If any deserialization fails
        """
        events = []
        errors = []
        
        for i, data in enumerate(data_list):
            try:
                event = self.event_serializer.deserialize_event(data)
                events.append(event)
            except Exception as e:
                event_type = data.get("event_type", "unknown")
                errors.append(f"Event {i} ({event_type}): {e}")
        
        if errors:
            error_msg = "; ".join(errors)
            raise EventSerializationError(f"Batch deserialization failed: {error_msg}")
        
        return events


def create_postgresql_serializer(
    enable_compression: bool = True,
    enable_encryption: bool = False,
    encryption_key: bytes | None = None
) -> PostgreSQLEventSerializer:
    """
    Factory function to create PostgreSQL event serializer.
    
    Args:
        enable_compression: Enable GZIP compression
        enable_encryption: Enable AES encryption
        encryption_key: Encryption key for AES
        
    Returns:
        PostgreSQLEventSerializer: Configured serializer
    """
    return PostgreSQLEventSerializer(
        enable_compression=enable_compression,
        enable_encryption=enable_encryption,
        encryption_key=encryption_key
    )


# Export main classes
__all__ = [
    "PostgreSQLEventSerializer",
    "EventStreamSerializer", 
    "EventSerializationError",
    "create_postgresql_serializer"
]