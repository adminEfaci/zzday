"""
Event store data schemas and models.

Defines the core data structures used throughout the event store infrastructure.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


class EventStatus(Enum):
    """Event processing status."""
    PENDING = "pending"
    PROCESSED = "processed"
    FAILED = "failed"
    ARCHIVED = "archived"


class CompressionType(Enum):
    """Event data compression types."""
    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"
    ZSTD = "zstd"


class EncryptionType(Enum):
    """Event data encryption types."""
    NONE = "none"
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"


@dataclass
class EventMetadata:
    """
    Event metadata containing processing and audit information.
    
    This metadata provides context about event processing, compliance,
    and technical details needed for debugging and audit purposes.
    """
    # Source information
    correlation_id: str | None = None
    causation_id: str | None = None
    source_service: str | None = None
    source_version: str | None = None
    
    # Processing information
    processed_at: datetime | None = None
    processed_by: str | None = None
    retry_count: int = 0
    
    # Audit and compliance
    user_id: UUID | None = None
    session_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    gdpr_compliant: bool = True
    retention_until: datetime | None = None
    
    # Technical metadata
    compression: CompressionType = CompressionType.NONE
    encryption: EncryptionType = EncryptionType.NONE
    checksum: str | None = None
    original_size: int | None = None
    compressed_size: int | None = None
    
    # Custom metadata
    custom: dict[str, Any] = field(default_factory=dict)


@dataclass
class EventRecord:
    """
    Complete event record as stored in the event store.
    
    This represents the full event data including both domain event
    information and storage metadata.
    """
    # Primary identifiers
    event_id: UUID
    aggregate_id: UUID
    aggregate_type: str
    event_type: str
    
    # Event versioning
    event_version: int
    aggregate_version: int
    
    # Event data
    event_data: dict[str, Any]
    metadata: EventMetadata
    
    # Storage timestamps
    created_at: datetime
    stored_at: datetime
    
    # Status tracking
    status: EventStatus = EventStatus.PENDING
    error_message: str | None = None
    
    # Stream information
    stream_id: str = ""
    stream_position: int = 0
    global_position: int = 0
    
    def __post_init__(self):
        """Set default stream_id if not provided."""
        if not self.stream_id:
            self.stream_id = f"{self.aggregate_type}-{self.aggregate_id}"


@dataclass
class EventSearchCriteria:
    """
    Criteria for searching and filtering events.
    
    Provides flexible filtering capabilities for event queries
    with performance optimizations and compliance features.
    """
    # Basic filters
    aggregate_ids: list[UUID] | None = None
    aggregate_types: list[str] | None = None
    event_types: list[str] | None = None
    
    # Time range filters
    from_timestamp: datetime | None = None
    to_timestamp: datetime | None = None
    from_version: int | None = None
    to_version: int | None = None
    
    # Stream filters
    stream_ids: list[str] | None = None
    from_position: int | None = None
    to_position: int | None = None
    
    # Status filters
    statuses: list[EventStatus] | None = None
    
    # User/audit filters
    user_ids: list[UUID] | None = None
    correlation_ids: list[str] | None = None
    
    # Pagination
    offset: int = 0
    limit: int = 100
    
    # Sorting
    sort_by: str = "created_at"
    sort_order: str = "asc"  # asc or desc
    
    # Performance hints
    include_event_data: bool = True
    include_metadata: bool = True


@dataclass
class EventFilter:
    """
    Advanced event filtering with custom conditions.
    
    Allows for complex filtering logic beyond basic criteria.
    """
    # Field-based filters
    field_filters: dict[str, Any] = field(default_factory=dict)
    
    # Custom JSON path filters for event_data
    json_path_filters: dict[str, Any] = field(default_factory=dict)
    
    # Text search in event data
    text_search: str | None = None
    search_fields: list[str] = field(default_factory=list)
    
    # Logical operators
    and_conditions: list['EventFilter'] = field(default_factory=list)
    or_conditions: list['EventFilter'] = field(default_factory=list)
    not_conditions: list['EventFilter'] = field(default_factory=list)


@dataclass
class EventSearchResult:
    """
    Result of an event search operation.
    
    Contains the matched events plus metadata about the search operation.
    """
    events: list[EventRecord]
    total_count: int
    page_count: int
    current_page: int
    has_more: bool
    
    # Search metadata
    search_duration_ms: float
    cache_hit: bool = False
    
    # Compliance information
    filtered_count: int = 0  # Events filtered due to access permissions
    anonymized_count: int = 0  # Events with anonymized data


@dataclass
class SnapshotRecord:
    """
    Aggregate snapshot record for performance optimization.
    
    Stores the state of an aggregate at a specific version to avoid
    replaying all events from the beginning.
    """
    snapshot_id: UUID
    aggregate_id: UUID
    aggregate_type: str
    aggregate_version: int
    
    # Snapshot data
    snapshot_data: dict[str, Any]
    metadata: EventMetadata
    
    # Timestamps
    created_at: datetime
    
    # Compression and encryption
    compression: CompressionType = CompressionType.GZIP
    encryption: EncryptionType = EncryptionType.NONE
    
    # Size tracking
    original_size: int = 0
    compressed_size: int = 0


@dataclass
class StreamPosition:
    """
    Position within an event stream.
    
    Used for tracking read progress and ensuring consistent
    event stream processing.
    """
    stream_id: str
    position: int
    global_position: int
    timestamp: datetime
    
    # Checkpoint information
    checkpoint_name: str | None = None
    consumer_group: str | None = None


@dataclass
class EventStoreMetrics:
    """
    Metrics and statistics about event store operations.
    
    Used for monitoring, performance tuning, and capacity planning.
    """
    # Event counts
    total_events: int = 0
    events_per_second: float = 0.0
    
    # Storage metrics
    total_storage_bytes: int = 0
    compressed_storage_bytes: int = 0
    compression_ratio: float = 0.0
    
    # Performance metrics
    avg_write_latency_ms: float = 0.0
    avg_read_latency_ms: float = 0.0
    cache_hit_ratio: float = 0.0
    
    # Error rates
    error_rate: float = 0.0
    retry_rate: float = 0.0
    
    # Timestamp
    measured_at: datetime = field(default_factory=datetime.utcnow)