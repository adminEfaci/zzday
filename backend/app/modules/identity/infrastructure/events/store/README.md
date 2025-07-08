# Event Store Infrastructure

A comprehensive event persistence and replay infrastructure for the identity module's event system, providing robust audit capabilities, debugging support, and recovery mechanisms with GDPR compliance.

## Overview

This event store infrastructure provides enterprise-grade event persistence with:

- **High-Performance Storage**: PostgreSQL implementation with partitioning, compression, and optimization
- **Event Sourcing Support**: Complete aggregate reconstruction from events
- **GDPR Compliance**: Event anonymization, deletion, and audit trails
- **Advanced Querying**: Complex filtering, full-text search, and pattern matching
- **Real-time Streaming**: Efficient event stream processing with checkpointing
- **Snapshot Optimization**: Performance optimization through aggregate snapshots
- **Archival Management**: Automated retention policies and cold storage
- **Replay Capabilities**: Event replay for debugging and recovery

## Core Components

### 1. EventStore Interface (`event_store.py`)
Abstract base class defining the core event store interface with comprehensive operations for:
- Event persistence with optimistic concurrency control
- Event querying and filtering
- Snapshot management
- GDPR compliance operations
- Performance monitoring

### 2. PostgreSQL Implementation (`postgresql_event_store.py`)
High-performance PostgreSQL implementation featuring:
- **Partitioned Tables**: Monthly partitioning for scalability
- **Compression**: Automatic event data compression
- **Indexing**: Optimized indexes for query performance
- **Concurrent Writes**: Optimistic locking for concurrent event streams
- **Health Monitoring**: Built-in health checks and metrics

### 3. Event Snapshots (`event_snapshot.py`)
Performance optimization through aggregate snapshots:
- **Multiple Strategies**: Event count, time-based, and adaptive strategies
- **Automatic Creation**: Configurable snapshot creation policies
- **Compression**: Efficient snapshot storage
- **Reconstruction**: Fast aggregate loading from snapshots + events

### 4. Event Replay Service (`event_replay_service.py`)
Comprehensive event replay for debugging and recovery:
- **Flexible Replay**: Time-based, aggregate-specific, and criteria-based replay
- **Error Handling**: Retry mechanisms and error tracking
- **Progress Tracking**: Real-time progress monitoring
- **Handler Registration**: Custom event processing handlers

### 5. Event Archiver (`event_archiver.py`)
Automated event archival and retention management:
- **GDPR Compliance**: Automated data retention and anonymization
- **Multiple Strategies**: Time, count, size, and compliance-based archival
- **External Storage**: Support for S3, GCS, Azure Blob, and file systems
- **Preview Mode**: Dry-run capabilities for testing policies

### 6. Event Query Service (`event_query_service.py`)
Advanced querying capabilities:
- **Complex Filtering**: JSON path filters and logical operators
- **Performance Optimization**: Query caching and optimization suggestions
- **Full-text Search**: Search within event data and metadata
- **Anomaly Detection**: Statistical analysis for anomalous events

### 7. Event Stream Reader (`event_stream_reader.py`)
High-performance stream processing:
- **Multiple Modes**: Batch, streaming, catch-up, and replay modes
- **Checkpointing**: Reliable progress tracking
- **Parallel Processing**: Configurable parallel event processing
- **Backpressure Handling**: Queue management and flow control

## Database Schema

### Core Tables

```sql
-- Events table (partitioned by created_at)
CREATE TABLE events.events (
    event_id UUID PRIMARY KEY,
    aggregate_id UUID NOT NULL,
    aggregate_type VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    event_version INTEGER NOT NULL,
    aggregate_version INTEGER NOT NULL,
    stream_id VARCHAR(500) NOT NULL,
    stream_position INTEGER NOT NULL,
    global_position BIGSERIAL,
    event_data JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    compression VARCHAR(20) DEFAULT 'none',
    encryption VARCHAR(30) DEFAULT 'none',
    checksum VARCHAR(64),
    original_size INTEGER,
    compressed_size INTEGER
) PARTITION BY RANGE (created_at);

-- Event snapshots table
CREATE TABLE events.event_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    aggregate_type VARCHAR(255) NOT NULL,
    aggregate_version INTEGER NOT NULL,
    snapshot_data JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    compression VARCHAR(20) DEFAULT 'gzip',
    encryption VARCHAR(30) DEFAULT 'none',
    original_size INTEGER,
    compressed_size INTEGER,
    UNIQUE(aggregate_id, aggregate_type, aggregate_version)
);

-- Stream checkpoints table
CREATE TABLE events.stream_checkpoints (
    checkpoint_name VARCHAR(255) NOT NULL,
    consumer_group VARCHAR(255),
    stream_id VARCHAR(500) NOT NULL,
    position INTEGER NOT NULL,
    global_position BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (checkpoint_name, consumer_group, stream_id)
);

-- Event access log (GDPR compliance)
CREATE TABLE events.event_access_log (
    access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID,
    aggregate_id UUID,
    user_id UUID,
    access_type VARCHAR(50) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    purpose TEXT
);
```

### Performance Indexes

```sql
-- Core lookup indexes
CREATE INDEX idx_events_aggregate ON events.events (aggregate_id, aggregate_type);
CREATE INDEX idx_events_stream ON events.events (stream_id, stream_position);
CREATE INDEX idx_events_type ON events.events (event_type);
CREATE INDEX idx_events_global_pos ON events.events (global_position);
CREATE INDEX idx_events_created_at ON events.events (created_at);

-- JSON indexes for metadata queries
CREATE INDEX idx_events_metadata_user ON events.events USING GIN ((metadata->>'user_id'));
CREATE INDEX idx_events_metadata_correlation ON events.events USING GIN ((metadata->>'correlation_id'));

-- Snapshot indexes
CREATE INDEX idx_snapshots_aggregate ON events.event_snapshots (aggregate_id, aggregate_type, aggregate_version DESC);
```

## Usage Examples

### Basic Event Storage

```python
from uuid import uuid4
from datetime import datetime, timezone

# Initialize event store
event_store = PostgreSQLEventStore(connection_pool, schema_name="events")
await event_store.initialize_schema()

# Create and store an event
event = EventRecord(
    event_id=uuid4(),
    aggregate_id=user_id,
    aggregate_type="User",
    event_type="UserCreated",
    event_version=1,
    aggregate_version=1,
    event_data={"email": "user@example.com", "name": "John Doe"},
    metadata=EventMetadata(user_id=user_id, gdpr_compliant=True),
    created_at=datetime.now(timezone.utc),
    stored_at=datetime.now(timezone.utc)
)

stream_id = f"User-{user_id}"
await event_store.append_events(stream_id, [event])
```

### Event Querying

```python
# Initialize query service
query_service = EventQueryService(event_store)

# Search for user events
criteria = EventSearchCriteria(
    aggregate_ids=[user_id],
    event_types=["UserCreated", "UserUpdated"],
    from_timestamp=datetime.now(timezone.utc) - timedelta(days=30)
)

result, metrics = await query_service.query_events(criteria)
print(f"Found {len(result.events)} events in {metrics.query_duration_ms}ms")

# Full-text search in event data
events = await query_service.search_event_content(
    "email@example.com",
    event_types=["UserCreated", "UserUpdated"]
)
```

### Event Replay

```python
# Initialize replay service
replay_service = EventReplayService(event_store)

# Register event handler
def handle_user_event(event: EventRecord):
    print(f"Processing: {event.event_type} for user {event.aggregate_id}")

replay_service.register_event_handler("UserCreated", handle_user_event)

# Replay recent events
config = ReplayConfig(
    from_timestamp=datetime.now(timezone.utc) - timedelta(hours=24),
    event_types=["UserCreated", "UserUpdated"],
    batch_size=100
)

result = await replay_service.replay_events(config)
print(f"Replayed {result.successful_events} events")
```

### Snapshot Management

```python
# Initialize snapshot service
snapshot_service = EventSnapshot(
    event_store,
    SnapshotConfig(
        strategy=SnapshotStrategy.EVENT_COUNT,
        event_threshold=50
    )
)

# Load aggregate with snapshot optimization
user, version = await snapshot_service.load_aggregate_with_events(
    User, user_id, "User"
)

# Create snapshot manually
await snapshot_service.create_snapshot(
    user, user_id, "User", version
)
```

### Stream Processing

```python
# Configure stream reader
config = StreamConfig(
    consumer_group="user-analytics",
    read_mode=StreamReadMode.STREAMING,
    batch_size=50,
    event_types=["UserCreated", "UserUpdated"],
    event_handler=lambda event: print(f"Processing: {event.event_type}")
)

# Start stream processing
stream_reader = EventStreamReader(event_store, config)
metrics = await stream_reader.process_stream()

print(f"Processed {metrics.events_processed} events")
print(f"Rate: {metrics.processing_rate_per_second} events/sec")
```

### GDPR Compliance

```python
# Initialize archiver with GDPR policy
archiver = EventArchiver(event_store)

gdpr_policy = ArchivalPolicy(
    policy_name="gdpr_compliance",
    strategy=ArchivalStrategy.GDPR_BASED,
    gdpr_retention_days=2555,  # 7 years
    anonymize_before_archive=True
)

archiver.register_policy(gdpr_policy)

# Clean up user data for GDPR
result = await archiver.cleanup_gdpr_data(user_id, anonymize=True)
print(f"Anonymized {result.events_anonymized} events")
```

## Performance Features

### Compression
- Automatic GZIP compression for event data
- Configurable compression algorithms (GZIP, LZ4, ZSTD)
- Size tracking for storage optimization

### Partitioning
- Monthly table partitioning for scalability
- Automatic partition creation and management
- Partition pruning for query optimization

### Caching
- Query result caching with TTL
- Configurable cache size and eviction policies
- Cache hit rate monitoring

### Indexing
- Optimized indexes for common query patterns
- JSON indexes for metadata searches
- Composite indexes for multi-column queries

## Monitoring and Metrics

### Event Store Metrics
- Total events processed
- Storage utilization and compression ratios
- Query performance statistics
- Error rates and retry statistics

### Stream Processing Metrics
- Processing rates and throughput
- Consumer lag and checkpoint progress
- Error rates and recovery statistics

### Query Performance
- Query duration and optimization suggestions
- Cache hit rates and effectiveness
- Index usage and performance analysis

## Configuration

### Environment Variables
```bash
# Database connection
DATABASE_URL=postgresql://user:password@localhost/eventstore
EVENT_STORE_SCHEMA=events

# Performance tuning
EVENT_STORE_COMPRESSION=true
EVENT_STORE_BATCH_SIZE=1000
EVENT_STORE_CACHE_TTL=300

# GDPR compliance
EVENT_STORE_ENCRYPTION=true
EVENT_STORE_RETENTION_DAYS=2555
```

### Schema Configuration
- Configurable schema name for multi-tenancy
- Customizable table names and indexes
- Flexible partitioning strategies

## Error Handling

### Concurrency Control
- Optimistic locking with version checking
- Conflict detection and resolution
- Retry mechanisms for transient failures

### Data Integrity
- Event checksums for corruption detection
- Atomic operations with transactions
- Backup and recovery procedures

### Monitoring
- Health check endpoints
- Error logging and alerting
- Performance degradation detection

## Security

### Data Protection
- Event encryption at rest
- Secure key management
- Access control and authentication

### Audit Trail
- Complete access logging
- GDPR compliance tracking
- Security event monitoring

### Privacy
- Data anonymization capabilities
- Right to be forgotten implementation
- Consent management integration

This event store infrastructure provides a robust foundation for event-driven architecture with enterprise-grade features for performance, reliability, and compliance.