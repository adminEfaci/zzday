"""
Event snapshots for performance optimization.

Provides snapshot functionality to avoid replaying all events when
reconstructing aggregates, improving performance for long-lived aggregates.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar
from uuid import UUID

from .event_store import EventStore
from .schemas import SnapshotRecord

T = TypeVar('T')


class SnapshotStrategy(Enum):
    """Snapshot creation strategies."""
    NEVER = "never"              # Never create snapshots
    EVENT_COUNT = "event_count"  # Create after N events
    TIME_BASED = "time_based"    # Create after time interval
    MANUAL = "manual"            # Only create manually
    SMART = "smart"              # Adaptive based on aggregate activity


@dataclass
class SnapshotConfig:
    """Configuration for snapshot behavior."""
    strategy: SnapshotStrategy = SnapshotStrategy.EVENT_COUNT
    event_threshold: int = 50     # Events before creating snapshot
    time_threshold_hours: int = 24  # Hours before creating time-based snapshot
    max_snapshots_per_aggregate: int = 10  # Keep only N latest snapshots
    compression_enabled: bool = True
    encryption_enabled: bool = False


class SnapshotSerializer(ABC, Generic[T]):
    """Abstract base class for aggregate snapshot serialization."""
    
    @abstractmethod
    def serialize(self, aggregate: T) -> dict[str, Any]:
        """Serialize aggregate to snapshot data."""
    
    @abstractmethod
    def deserialize(self, snapshot_data: dict[str, Any], aggregate_type: type[T]) -> T:
        """Deserialize snapshot data to aggregate."""


class DefaultSnapshotSerializer(SnapshotSerializer[T]):
    """Default JSON-based snapshot serializer."""
    
    def serialize(self, aggregate: T) -> dict[str, Any]:
        """Serialize aggregate using its __dict__."""
        if hasattr(aggregate, '__dict__'):
            data = {}
            for key, value in aggregate.__dict__.items():
                if not key.startswith('_'):  # Skip private attributes
                    data[key] = self._serialize_value(value)
            return data
        raise ValueError(f"Cannot serialize aggregate of type {type(aggregate)}")
    
    def deserialize(self, snapshot_data: dict[str, Any], aggregate_type: type[T]) -> T:
        """Deserialize snapshot data to aggregate instance."""
        try:
            # Try to create instance with snapshot data as kwargs
            return aggregate_type(**snapshot_data)
        except Exception as e:
            raise ValueError(f"Cannot deserialize snapshot for {aggregate_type}: {e}")
    
    def _serialize_value(self, value: Any) -> Any:
        """Serialize individual values."""
        if isinstance(value, str | int | float | bool | type(None)):
            return value
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, list | tuple):
            return [self._serialize_value(item) for item in value]
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}
        if hasattr(value, '__dict__'):
            return self._serialize_value(value.__dict__)
        return str(value)  # Fallback to string representation


class EventSnapshot:
    """
    Manages aggregate snapshots for performance optimization.
    
    Provides functionality to create, store, and retrieve snapshots
    of aggregate state to avoid replaying all events from the beginning.
    """
    
    def __init__(
        self,
        event_store: EventStore,
        config: SnapshotConfig | None = None,
        serializer: SnapshotSerializer | None = None
    ):
        self.event_store = event_store
        self.config = config or SnapshotConfig()
        self.serializer = serializer or DefaultSnapshotSerializer()
        
        # Track snapshot creation stats
        self._snapshots_created = 0
        self._snapshots_loaded = 0
        self._snapshot_misses = 0
    
    async def should_create_snapshot(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        current_version: int
    ) -> bool:
        """
        Determine if a snapshot should be created based on the configured strategy.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            current_version: Current version of the aggregate
            
        Returns:
            True if a snapshot should be created
        """
        if self.config.strategy == SnapshotStrategy.NEVER:
            return False
        
        if self.config.strategy == SnapshotStrategy.MANUAL:
            return False  # Only create when explicitly requested
        
        # Get latest snapshot to compare
        latest_snapshot = await self.event_store.get_latest_snapshot(
            aggregate_id, aggregate_type
        )
        
        if self.config.strategy == SnapshotStrategy.EVENT_COUNT:
            if not latest_snapshot:
                # Create first snapshot if we have enough events
                return current_version >= self.config.event_threshold
            # Create if enough events since last snapshot
            events_since_snapshot = current_version - latest_snapshot.aggregate_version
            return events_since_snapshot >= self.config.event_threshold
        
        if self.config.strategy == SnapshotStrategy.TIME_BASED:
            if not latest_snapshot:
                return True  # Create first snapshot immediately
            # Create if enough time has passed
            time_since_snapshot = datetime.now(UTC) - latest_snapshot.created_at
            return time_since_snapshot.total_seconds() >= (self.config.time_threshold_hours * 3600)
        
        if self.config.strategy == SnapshotStrategy.SMART:
            # Adaptive strategy based on aggregate activity
            return await self._smart_snapshot_decision(
                aggregate_id, aggregate_type, current_version, latest_snapshot
            )
        
        return False
    
    async def create_snapshot(
        self,
        aggregate: Any,
        aggregate_id: UUID,
        aggregate_type: str,
        version: int,
        metadata: dict[str, Any] | None = None
    ) -> SnapshotRecord:
        """
        Create a snapshot of an aggregate.
        
        Args:
            aggregate: The aggregate instance to snapshot
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            version: The aggregate version
            metadata: Additional metadata for the snapshot
            
        Returns:
            Created snapshot record
        """
        # Serialize aggregate data
        snapshot_data = self.serializer.serialize(aggregate)
        
        # Create metadata
        snapshot_metadata = {
            "created_by": "snapshot_service",
            "strategy": self.config.strategy.value,
            "serializer": type(self.serializer).__name__,
            **(metadata or {})
        }
        
        # Create snapshot in event store
        snapshot_record = await self.event_store.create_snapshot(
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            version=version,
            snapshot_data=snapshot_data,
            metadata=snapshot_metadata
        )
        
        # Clean up old snapshots if needed
        await self._cleanup_old_snapshots(aggregate_id, aggregate_type)
        
        self._snapshots_created += 1
        return snapshot_record
    
    async def load_aggregate_from_snapshot(
        self,
        aggregate_type: type[T],
        aggregate_id: UUID,
        aggregate_type_name: str,
        max_version: int | None = None
    ) -> tuple[T, int] | None:
        """
        Load an aggregate from its latest snapshot.
        
        Args:
            aggregate_type: The aggregate class type
            aggregate_id: The aggregate identifier
            aggregate_type_name: The aggregate type name
            max_version: Maximum version to consider
            
        Returns:
            Tuple of (aggregate_instance, snapshot_version) or None if no snapshot
        """
        # Get latest snapshot
        snapshot_record = await self.event_store.get_latest_snapshot(
            aggregate_id, aggregate_type_name, max_version
        )
        
        if not snapshot_record:
            self._snapshot_misses += 1
            return None
        
        try:
            # Deserialize aggregate from snapshot
            aggregate = self.serializer.deserialize(
                snapshot_record.snapshot_data, aggregate_type
            )
            
            self._snapshots_loaded += 1
            return aggregate, snapshot_record.aggregate_version
        
        except Exception as e:
            # Log error and return None to fall back to event replay
            print(f"Failed to deserialize snapshot for {aggregate_id}: {e}")
            self._snapshot_misses += 1
            return None
    
    async def load_aggregate_with_events(
        self,
        aggregate_type: type[T],
        aggregate_id: UUID,
        aggregate_type_name: str,
        target_version: int | None = None
    ) -> tuple[T, int] | None:
        """
        Load an aggregate using snapshot + events for optimal performance.
        
        This method first attempts to load from a snapshot, then applies
        any events that occurred after the snapshot was created.
        
        Args:
            aggregate_type: The aggregate class type
            aggregate_id: The aggregate identifier
            aggregate_type_name: The aggregate type name
            target_version: Target version to load (None for latest)
            
        Returns:
            Tuple of (aggregate_instance, final_version) or None
        """
        # Try to load from snapshot first
        snapshot_result = await self.load_aggregate_from_snapshot(
            aggregate_type, aggregate_id, aggregate_type_name, target_version
        )
        
        if snapshot_result:
            aggregate, snapshot_version = snapshot_result
            
            # Get events after snapshot
            events = await self.event_store.get_aggregate_events(
                aggregate_id, aggregate_type_name, snapshot_version + 1
            )
            
            # Filter events up to target version if specified
            if target_version is not None:
                events = [e for e in events if e.aggregate_version <= target_version]
            
            # Apply events to aggregate
            final_version = snapshot_version
            for event in events:
                if hasattr(aggregate, 'apply_event'):
                    aggregate.apply_event(event)
                final_version = event.aggregate_version
            
            return aggregate, final_version
        
        # No snapshot available, load from all events
        events = await self.event_store.get_aggregate_events(
            aggregate_id, aggregate_type_name
        )

        if not events:
            return None

        # Filter events up to target version if specified
        if target_version is not None:
            events = [e for e in events if e.aggregate_version <= target_version]

        if not events:
            return None

        # Create aggregate from first event
        events[0]
        if hasattr(aggregate_type, 'from_events'):
            aggregate = aggregate_type.from_events(events)
            return aggregate, events[-1].aggregate_version
        # Fallback: try to create empty aggregate and apply events
        try:
            aggregate = aggregate_type()
            for event in events:
                if hasattr(aggregate, 'apply_event'):
                    aggregate.apply_event(event)
            return aggregate, events[-1].aggregate_version
        except Exception:
            return None
    
    async def delete_snapshots(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        keep_latest: int = 0
    ) -> int:
        """
        Delete snapshots for an aggregate.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            keep_latest: Number of latest snapshots to keep
            
        Returns:
            Number of snapshots deleted
        """
        # This would need to be implemented in the event store
        # For now, return 0 as placeholder
        return 0
    
    async def get_snapshot_metrics(self) -> dict[str, Any]:
        """Get metrics about snapshot usage."""
        return {
            "snapshots_created": self._snapshots_created,
            "snapshots_loaded": self._snapshots_loaded,
            "snapshot_misses": self._snapshot_misses,
            "hit_rate": (
                self._snapshots_loaded / (self._snapshots_loaded + self._snapshot_misses)
                if (self._snapshots_loaded + self._snapshot_misses) > 0 else 0
            ),
            "config": {
                "strategy": self.config.strategy.value,
                "event_threshold": self.config.event_threshold,
                "time_threshold_hours": self.config.time_threshold_hours
            }
        }
    
    async def _smart_snapshot_decision(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        current_version: int,
        latest_snapshot: SnapshotRecord | None
    ) -> bool:
        """
        Smart adaptive strategy for snapshot creation.
        
        Takes into account:
        - Event frequency
        - Aggregate size
        - Query patterns
        - Storage costs
        """
        # Get aggregate metadata to understand activity
        stream_id = f"{aggregate_type}-{aggregate_id}"
        await self.event_store.get_stream_metadata(stream_id)
        
        if not latest_snapshot:
            # Create first snapshot after some activity
            return current_version >= 10
        
        events_since_snapshot = current_version - latest_snapshot.aggregate_version
        time_since_snapshot = datetime.now(UTC) - latest_snapshot.created_at
        
        # High activity aggregates get more frequent snapshots
        if events_since_snapshot >= 100:  # Very active
            return True
        
        # Medium activity with time factor
        if events_since_snapshot >= 25 and time_since_snapshot.total_seconds() >= 3600:
            return True
        
        # Low activity with longer time factor
        return bool(events_since_snapshot >= 10 and time_since_snapshot.total_seconds() >= 86400)
    
    async def _cleanup_old_snapshots(
        self,
        aggregate_id: UUID,
        aggregate_type: str
    ) -> None:
        """Clean up old snapshots beyond the retention limit."""
        if self.config.max_snapshots_per_aggregate <= 0:
            return  # No limit set
        
        # This would need to be implemented in the event store
        # to get all snapshots and delete old ones beyond the limit
