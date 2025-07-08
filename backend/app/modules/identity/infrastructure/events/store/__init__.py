"""
Event store infrastructure for identity module.

This package provides comprehensive event persistence, replay, and audit capabilities
for the identity module's event system. It supports event sourcing patterns,
GDPR compliance, and audit trail requirements.

Key Components:
- EventStore: Main event storage interface
- PostgreSQLEventStore: PostgreSQL implementation with performance optimizations
- EventSnapshot: Snapshots for aggregate reconstruction performance
- EventReplayService: Event replay for debugging and recovery
- EventArchiver: Event archiving and retention management
- EventQueryService: Complex event querying and filtering
- EventStreamReader: Efficient event stream processing

Database Schema:
- events: Core event storage with partitioning
- event_snapshots: Aggregate state snapshots
- event_subscriptions: Event subscription management
- event_access_log: Audit trail for event access (GDPR compliance)

Performance Features:
- Event compression for storage efficiency
- Event encryption for sensitive data
- Concurrent event writing with optimistic locking
- Index optimization for query performance
- Partitioning for large event volumes

Compliance Features:
- GDPR-compliant event anonymization
- Audit trail for all event access
- Data retention and deletion policies
- Event encryption for sensitive information
"""

from .event_archiver import ArchivalPolicy, EventArchiver
from .event_query_service import EventFilter, EventQueryService, EventSearchCriteria
from .event_replay_service import EventReplayService, ReplayConfig
from .event_snapshot import EventSnapshot, SnapshotStrategy
from .event_store import EventConflictError, EventStore, EventStoreError
from .event_stream_reader import EventStreamReader, StreamConfig
from .postgresql_event_store import PostgreSQLEventStore
from .schemas import EventMetadata, EventRecord, EventSearchResult

__all__ = [
    'ArchivalPolicy',
    'EventArchiver',
    'EventConflictError',
    'EventFilter',
    'EventMetadata',
    'EventQueryService',
    # Data models
    'EventRecord',
    'EventReplayService',
    'EventSearchCriteria',
    'EventSearchResult',
    'EventSnapshot',
    # Core interfaces
    'EventStore',
    'EventStoreError',
    'EventStreamReader',
    # Implementations
    'PostgreSQLEventStore',
    'ReplayConfig',
    'SnapshotStrategy',
    'StreamConfig',
]