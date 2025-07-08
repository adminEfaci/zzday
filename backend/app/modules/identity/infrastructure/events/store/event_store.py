"""
Event store interface and base implementations.

Defines the core event store interface with comprehensive event persistence,
querying, and management capabilities.
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any
from uuid import UUID

from .schemas import (
    EventFilter,
    EventRecord,
    EventSearchCriteria,
    EventSearchResult,
    EventStoreMetrics,
    SnapshotRecord,
    StreamPosition,
)


class EventStoreError(Exception):
    """Base exception for event store operations."""
    
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}


class EventConflictError(EventStoreError):
    """Raised when there's a conflict in event versioning or concurrency."""
    
    def __init__(
        self, 
        message: str, 
        expected_version: int, 
        actual_version: int,
        aggregate_id: UUID
    ):
        super().__init__(message)
        self.expected_version = expected_version
        self.actual_version = actual_version
        self.aggregate_id = aggregate_id


class EventStore(ABC):
    """
    Abstract base class for event store implementations.
    
    Provides a comprehensive interface for event persistence, querying,
    and management with support for event sourcing patterns, GDPR compliance,
    and high-performance operations.
    """
    
    @abstractmethod
    async def append_events(
        self,
        stream_id: str,
        events: list[EventRecord],
        expected_version: int | None = None
    ) -> None:
        """
        Append events to a stream with optimistic concurrency control.
        
        Args:
            stream_id: The stream identifier
            events: List of events to append
            expected_version: Expected current version for optimistic locking
            
        Raises:
            EventConflictError: If expected version doesn't match current version
            EventStoreError: For other storage-related errors
        """
    
    @abstractmethod
    async def get_events(
        self,
        stream_id: str,
        from_version: int | None = None,
        to_version: int | None = None
    ) -> list[EventRecord]:
        """
        Get events from a specific stream.
        
        Args:
            stream_id: The stream identifier
            from_version: Starting version (inclusive)
            to_version: Ending version (inclusive)
            
        Returns:
            List of events in the specified range
        """
    
    @abstractmethod
    async def get_aggregate_events(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        from_version: int | None = None
    ) -> list[EventRecord]:
        """
        Get all events for a specific aggregate.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            from_version: Starting version (inclusive)
            
        Returns:
            List of events for the aggregate
        """
    
    @abstractmethod
    async def search_events(
        self,
        criteria: EventSearchCriteria,
        event_filter: EventFilter | None = None
    ) -> EventSearchResult:
        """
        Search events based on complex criteria and filters.
        
        Args:
            criteria: Basic search criteria
            event_filter: Advanced filtering options
            
        Returns:
            Search results with pagination and metadata
        """
    
    @abstractmethod
    async def get_stream_metadata(self, stream_id: str) -> dict[str, Any]:
        """
        Get metadata about a specific stream.
        
        Args:
            stream_id: The stream identifier
            
        Returns:
            Stream metadata including version, event count, etc.
        """
    
    @abstractmethod
    async def create_snapshot(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        version: int,
        snapshot_data: dict[str, Any],
        metadata: dict[str, Any] | None = None
    ) -> SnapshotRecord:
        """
        Create a snapshot of an aggregate at a specific version.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            version: The aggregate version at snapshot time
            snapshot_data: The serialized aggregate state
            metadata: Additional snapshot metadata
            
        Returns:
            Created snapshot record
        """
    
    @abstractmethod
    async def get_latest_snapshot(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        max_version: int | None = None
    ) -> SnapshotRecord | None:
        """
        Get the latest snapshot for an aggregate.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            max_version: Maximum version to consider
            
        Returns:
            Latest snapshot record or None if no snapshots exist
        """
    
    @abstractmethod
    async def delete_events(
        self,
        criteria: EventSearchCriteria,
        soft_delete: bool = True
    ) -> int:
        """
        Delete events based on criteria (for GDPR compliance).
        
        Args:
            criteria: Criteria for selecting events to delete
            soft_delete: Whether to soft delete (mark as deleted) or hard delete
            
        Returns:
            Number of events deleted
        """
    
    @abstractmethod
    async def anonymize_events(
        self,
        criteria: EventSearchCriteria,
        anonymization_map: dict[str, str]
    ) -> int:
        """
        Anonymize events for GDPR compliance.
        
        Args:
            criteria: Criteria for selecting events to anonymize
            anonymization_map: Mapping of field paths to anonymization strategies
            
        Returns:
            Number of events anonymized
        """
    
    @abstractmethod
    async def archive_events(
        self,
        criteria: EventSearchCriteria,
        archive_location: str
    ) -> int:
        """
        Archive old events to external storage.
        
        Args:
            criteria: Criteria for selecting events to archive
            archive_location: Location to archive events to
            
        Returns:
            Number of events archived
        """
    
    @abstractmethod
    async def get_metrics(
        self,
        from_time: datetime | None = None,
        to_time: datetime | None = None
    ) -> EventStoreMetrics:
        """
        Get event store metrics and statistics.
        
        Args:
            from_time: Start time for metrics calculation
            to_time: End time for metrics calculation
            
        Returns:
            Event store metrics
        """
    
    @abstractmethod
    async def create_stream_reader(
        self,
        stream_id: str,
        from_position: int | None = None,
        batch_size: int = 100
    ) -> AsyncIterator[list[EventRecord]]:
        """
        Create an async iterator for reading events from a stream.
        
        Args:
            stream_id: The stream identifier
            from_position: Starting position
            batch_size: Number of events to read in each batch
            
        Yields:
            Batches of events from the stream
        """
    
    @abstractmethod
    async def get_checkpoint(
        self,
        checkpoint_name: str,
        consumer_group: str | None = None
    ) -> StreamPosition | None:
        """
        Get a checkpoint position for stream processing.
        
        Args:
            checkpoint_name: Name of the checkpoint
            consumer_group: Optional consumer group
            
        Returns:
            Checkpoint position or None if not found
        """
    
    @abstractmethod
    async def save_checkpoint(
        self,
        checkpoint_name: str,
        position: StreamPosition,
        consumer_group: str | None = None
    ) -> None:
        """
        Save a checkpoint position for stream processing.
        
        Args:
            checkpoint_name: Name of the checkpoint
            position: Position to save
            consumer_group: Optional consumer group
        """
    
    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """
        Perform a health check of the event store.
        
        Returns:
            Health status information
        """
    
    @abstractmethod
    async def optimize_storage(
        self,
        criteria: EventSearchCriteria | None = None
    ) -> dict[str, Any]:
        """
        Optimize storage by compacting, reindexing, or other operations.
        
        Args:
            criteria: Optional criteria to limit optimization scope
            
        Returns:
            Optimization results and statistics
        """
