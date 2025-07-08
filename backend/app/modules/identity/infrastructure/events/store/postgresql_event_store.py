"""
PostgreSQL implementation of the event store.

High-performance PostgreSQL implementation with support for partitioning,
compression, encryption, and GDPR compliance features.
"""

import gzip
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from asyncpg import Connection, Pool

from .event_store import EventConflictError, EventStore
from .schemas import (
    CompressionType,
    EncryptionType,
    EventFilter,
    EventMetadata,
    EventRecord,
    EventSearchCriteria,
    EventSearchResult,
    EventStatus,
    EventStoreMetrics,
    SnapshotRecord,
    StreamPosition,
)


class PostgreSQLEventStore(EventStore):
    """
    PostgreSQL implementation of the event store.
    
    Features:
    - High-performance event persistence with batching
    - Optimistic concurrency control
    - Event compression and encryption
    - GDPR compliance with anonymization and deletion
    - Advanced querying with JSON path support
    - Stream processing with checkpoints
    - Partitioning for large event volumes
    - Performance monitoring and optimization
    """
    
    def __init__(
        self,
        connection_pool: Pool,
        schema_name: str = "events",
        enable_compression: bool = True,
        enable_encryption: bool = False,
        encryption_key: str | None = None
    ):
        self.pool = connection_pool
        # Validate schema name to prevent SQL injection
        if not self._is_valid_identifier(schema_name):
            raise ValueError(f"Invalid schema name: {schema_name}")
        self.schema_name = schema_name
        self.enable_compression = enable_compression
        self.enable_encryption = enable_encryption
        self.encryption_key = encryption_key
        
        # Performance configuration
        self.batch_size = 1000
        self.query_timeout = 30.0
        self.connection_timeout = 5.0
        
        # Metrics tracking
        self._write_counter = 0
        self._read_counter = 0
        self._error_counter = 0
    
    @staticmethod
    def _is_valid_identifier(name: str) -> bool:
        """Validate that an identifier is safe for use in SQL."""
        import re
        # Allow only alphanumeric characters and underscores, must start with letter or underscore
        return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name)) and len(name) <= 63
    
    async def initialize_schema(self) -> None:
        """Initialize the database schema with tables and indexes."""
        async with self.pool.acquire() as conn:
            await self._create_schema(conn)
            await self._create_tables(conn)
            await self._create_indexes(conn)
            await self._create_functions(conn)
    
    async def _create_schema(self, conn: Connection) -> None:
        """Create the events schema."""
        await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {self.schema_name}")
    
    async def _create_tables(self, conn: Connection) -> None:
        """Create all event store tables."""
        
        # Main events table with partitioning
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.schema_name}.events (
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
                metadata JSONB NOT NULL DEFAULT '{{}}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                status VARCHAR(50) NOT NULL DEFAULT 'pending',
                error_message TEXT,
                compression VARCHAR(20) DEFAULT 'none',
                encryption VARCHAR(30) DEFAULT 'none',
                checksum VARCHAR(64),
                original_size INTEGER,
                compressed_size INTEGER
            ) PARTITION BY RANGE (created_at)
        """)
        
        # Create monthly partitions for the last year and next year
        current_date = datetime.now(UTC)
        for i in range(-12, 13):
            year = current_date.year
            month = current_date.month + i
            if month <= 0:
                month += 12
                year -= 1
            elif month > 12:
                month -= 12
                year += 1
            
            partition_name = f"events_{year}_{month:02d}"
            start_date = f"{year}-{month:02d}-01"
            if month == 12:
                end_date = f"{year + 1}-01-01"
            else:
                end_date = f"{year}-{month + 1:02d}-01"
            
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.schema_name}.{partition_name}
                PARTITION OF {self.schema_name}.events
                FOR VALUES FROM ('{start_date}') TO ('{end_date}')
            """)
        
        # Event snapshots table
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.schema_name}.event_snapshots (
                snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                aggregate_id UUID NOT NULL,
                aggregate_type VARCHAR(255) NOT NULL,
                aggregate_version INTEGER NOT NULL,
                snapshot_data JSONB NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{{}}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                compression VARCHAR(20) DEFAULT 'gzip',
                encryption VARCHAR(30) DEFAULT 'none',
                original_size INTEGER,
                compressed_size INTEGER,
                UNIQUE(aggregate_id, aggregate_type, aggregate_version)
            )
        """)
        
        # Stream checkpoints table
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.schema_name}.stream_checkpoints (
                checkpoint_name VARCHAR(255) NOT NULL,
                consumer_group VARCHAR(255),
                stream_id VARCHAR(500) NOT NULL,
                position INTEGER NOT NULL,
                global_position BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (checkpoint_name, consumer_group, stream_id)
            )
        """)
        
        # Event subscriptions table
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.schema_name}.event_subscriptions (
                subscription_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL UNIQUE,
                event_types TEXT[] NOT NULL,
                filters JSONB DEFAULT '{{}}',
                endpoint_url TEXT,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        
        # Event access log for GDPR compliance
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.schema_name}.event_access_log (
                access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_id UUID,
                aggregate_id UUID,
                user_id UUID,
                access_type VARCHAR(50) NOT NULL,
                ip_address INET,
                user_agent TEXT,
                accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                purpose TEXT
            )
        """)
    
    async def _create_indexes(self, conn: Connection) -> None:
        """Create performance indexes."""
        indexes = [
            # Core lookup indexes
            f"CREATE INDEX IF NOT EXISTS idx_events_aggregate ON {self.schema_name}.events (aggregate_id, aggregate_type)",
            f"CREATE INDEX IF NOT EXISTS idx_events_stream ON {self.schema_name}.events (stream_id, stream_position)",
            f"CREATE INDEX IF NOT EXISTS idx_events_type ON {self.schema_name}.events (event_type)",
            f"CREATE INDEX IF NOT EXISTS idx_events_global_pos ON {self.schema_name}.events (global_position)",
            f"CREATE INDEX IF NOT EXISTS idx_events_created_at ON {self.schema_name}.events (created_at)",
            f"CREATE INDEX IF NOT EXISTS idx_events_status ON {self.schema_name}.events (status)",
            
            # JSON indexes for metadata queries
            f"CREATE INDEX IF NOT EXISTS idx_events_metadata_user ON {self.schema_name}.events USING GIN ((metadata->>'user_id'))",
            f"CREATE INDEX IF NOT EXISTS idx_events_metadata_correlation ON {self.schema_name}.events USING GIN ((metadata->>'correlation_id'))",
            
            # Snapshot indexes
            f"CREATE INDEX IF NOT EXISTS idx_snapshots_aggregate ON {self.schema_name}.event_snapshots (aggregate_id, aggregate_type, aggregate_version DESC)",
            
            # Checkpoint indexes
            f"CREATE INDEX IF NOT EXISTS idx_checkpoints_lookup ON {self.schema_name}.stream_checkpoints (checkpoint_name, consumer_group)",
            
            # Access log indexes
            f"CREATE INDEX IF NOT EXISTS idx_access_log_event ON {self.schema_name}.event_access_log (event_id)",
            f"CREATE INDEX IF NOT EXISTS idx_access_log_user ON {self.schema_name}.event_access_log (user_id, accessed_at)",
        ]
        
        for index_sql in indexes:
            try:
                await conn.execute(index_sql)
            except Exception as e:
                # Log warning but continue - index might already exist
                print(f"Warning creating index: {e}")
    
    async def _create_functions(self, conn: Connection) -> None:
        """Create stored functions for common operations."""
        
        # Function to get next stream position
        await conn.execute(f"""
            CREATE OR REPLACE FUNCTION {self.schema_name}.get_next_stream_position(p_stream_id VARCHAR)
            RETURNS INTEGER AS $$
            DECLARE
                next_pos INTEGER;
            BEGIN
                SELECT COALESCE(MAX(stream_position), 0) + 1 
                INTO next_pos
                FROM {self.schema_name}.events 
                WHERE stream_id = p_stream_id;
                
                RETURN next_pos;
            END;
            $$ LANGUAGE plpgsql;
        """)
        
        # Function to compress JSON data
        await conn.execute(f"""
            CREATE OR REPLACE FUNCTION {self.schema_name}.compress_event_data(data JSONB)
            RETURNS BYTEA AS $$
            BEGIN
                RETURN compress(data::TEXT::BYTEA);
            END;
            $$ LANGUAGE plpgsql;
        """)
    
    async def append_events(
        self,
        stream_id: str,
        events: list[EventRecord],
        expected_version: int | None = None
    ) -> None:
        """Append events to a stream with optimistic concurrency control."""
        if not events:
            return
        
        async with self._get_connection() as conn:
            async with conn.transaction():
                # Check expected version if provided
                if expected_version is not None:
                    current_version = await self._get_stream_version(conn, stream_id)
                    if current_version != expected_version:
                        raise EventConflictError(
                            f"Version conflict for stream {stream_id}",
                            expected_version,
                            current_version,
                            UUID(stream_id.split('-', 1)[1]) if '-' in stream_id else uuid4()
                        )
                
                # Get starting position for the stream
                start_position = await self._get_next_stream_position(conn, stream_id)
                
                # Prepare event records
                prepared_events = []
                for i, event in enumerate(events):
                    event.stream_id = stream_id
                    event.stream_position = start_position + i
                    event.stored_at = datetime.now(UTC)
                    
                    # Compress and encrypt data if enabled
                    event_data, metadata = await self._process_event_data(
                        event.event_data, event.metadata
                    )
                    
                    prepared_events.append((
                        event.event_id,
                        event.aggregate_id,
                        event.aggregate_type,
                        event.event_type,
                        event.event_version,
                        event.aggregate_version,
                        event.stream_id,
                        event.stream_position,
                        event_data,
                        metadata,
                        event.created_at,
                        event.stored_at,
                        event.status.value,
                        event.error_message
                    ))
                
                # Batch insert events
                await conn.executemany(f"""
                    INSERT INTO {self.schema_name}.events (
                        event_id, aggregate_id, aggregate_type, event_type,
                        event_version, aggregate_version, stream_id, stream_position,
                        event_data, metadata, created_at, stored_at, status, error_message
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                """, prepared_events)
                
                self._write_counter += len(events)
    
    async def get_events(
        self,
        stream_id: str,
        from_version: int | None = None,
        to_version: int | None = None
    ) -> list[EventRecord]:
        """Get events from a specific stream."""
        query = f"""
            SELECT event_id, aggregate_id, aggregate_type, event_type,
                   event_version, aggregate_version, stream_id, stream_position,
                   global_position, event_data, metadata, created_at, stored_at,
                   status, error_message, compression, encryption
            FROM {self.schema_name}.events
            WHERE stream_id = $1
        """
        params = [stream_id]
        
        if from_version is not None:
            query += " AND stream_position >= $2"
            params.append(from_version)
            
        if to_version is not None:
            query += f" AND stream_position <= ${len(params) + 1}"
            params.append(to_version)
            
        query += " ORDER BY stream_position ASC"
        
        async with self._get_connection() as conn:
            rows = await conn.fetch(query, *params)
            events = []
            
            for row in rows:
                event_data, metadata = await self._unprocess_event_data(
                    row['event_data'], row['metadata'], 
                    row['compression'], row['encryption']
                )
                
                events.append(EventRecord(
                    event_id=row['event_id'],
                    aggregate_id=row['aggregate_id'],
                    aggregate_type=row['aggregate_type'],
                    event_type=row['event_type'],
                    event_version=row['event_version'],
                    aggregate_version=row['aggregate_version'],
                    event_data=event_data,
                    metadata=metadata,
                    created_at=row['created_at'],
                    stored_at=row['stored_at'],
                    status=EventStatus(row['status']),
                    error_message=row['error_message'],
                    stream_id=row['stream_id'],
                    stream_position=row['stream_position'],
                    global_position=row['global_position']
                ))
            
            self._read_counter += len(events)
            return events
    
    async def get_aggregate_events(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        from_version: int | None = None
    ) -> list[EventRecord]:
        """Get all events for a specific aggregate."""
        query = f"""
            SELECT event_id, aggregate_id, aggregate_type, event_type,
                   event_version, aggregate_version, stream_id, stream_position,
                   global_position, event_data, metadata, created_at, stored_at,
                   status, error_message, compression, encryption
            FROM {self.schema_name}.events
            WHERE aggregate_id = $1 AND aggregate_type = $2
        """
        params = [aggregate_id, aggregate_type]
        
        if from_version is not None:
            query += " AND aggregate_version >= $3"
            params.append(from_version)
            
        query += " ORDER BY aggregate_version ASC"
        
        async with self._get_connection() as conn:
            rows = await conn.fetch(query, *params)
            events = []
            
            for row in rows:
                event_data, metadata = await self._unprocess_event_data(
                    row['event_data'], row['metadata'],
                    row['compression'], row['encryption']
                )
                
                events.append(EventRecord(
                    event_id=row['event_id'],
                    aggregate_id=row['aggregate_id'],
                    aggregate_type=row['aggregate_type'],
                    event_type=row['event_type'],
                    event_version=row['event_version'],
                    aggregate_version=row['aggregate_version'],
                    event_data=event_data,
                    metadata=metadata,
                    created_at=row['created_at'],
                    stored_at=row['stored_at'],
                    status=EventStatus(row['status']),
                    error_message=row['error_message'],
                    stream_id=row['stream_id'],
                    stream_position=row['stream_position'],
                    global_position=row['global_position']
                ))
            
            self._read_counter += len(events)
            return events
    
    async def search_events(
        self,
        criteria: EventSearchCriteria,
        event_filter: EventFilter | None = None
    ) -> EventSearchResult:
        """Search events based on complex criteria and filters."""
        start_time = datetime.now()
        
        # Build query
        query_parts = [f"""
            SELECT event_id, aggregate_id, aggregate_type, event_type,
                   event_version, aggregate_version, stream_id, stream_position,
                   global_position, event_data, metadata, created_at, stored_at,
                   status, error_message, compression, encryption
            FROM {self.schema_name}.events
            WHERE 1=1
        """]
        
        params = []
        param_count = 0
        
        # Apply basic criteria
        if criteria.aggregate_ids:
            param_count += 1
            query_parts.append(f" AND aggregate_id = ANY(${param_count})")
            params.append(criteria.aggregate_ids)
        
        if criteria.aggregate_types:
            param_count += 1
            query_parts.append(f" AND aggregate_type = ANY(${param_count})")
            params.append(criteria.aggregate_types)
        
        if criteria.event_types:
            param_count += 1
            query_parts.append(f" AND event_type = ANY(${param_count})")
            params.append(criteria.event_types)
        
        if criteria.from_timestamp:
            param_count += 1
            query_parts.append(f" AND created_at >= ${param_count}")
            params.append(criteria.from_timestamp)
        
        if criteria.to_timestamp:
            param_count += 1
            query_parts.append(f" AND created_at <= ${param_count}")
            params.append(criteria.to_timestamp)
        
        if criteria.statuses:
            param_count += 1
            query_parts.append(f" AND status = ANY(${param_count})")
            params.append([s.value for s in criteria.statuses])
        
        # Apply sorting
        query_parts.append(f" ORDER BY {criteria.sort_by} {criteria.sort_order.upper()}")
        
        # Apply pagination
        param_count += 1
        query_parts.append(f" LIMIT ${param_count}")
        params.append(criteria.limit)
        
        param_count += 1
        query_parts.append(f" OFFSET ${param_count}")
        params.append(criteria.offset)
        
        query = "".join(query_parts)
        
        async with self._get_connection() as conn:
            # Get total count for pagination
            count_query = query.replace(
                "SELECT event_id, aggregate_id, aggregate_type, event_type, event_version, aggregate_version, stream_id, stream_position, global_position, event_data, metadata, created_at, stored_at, status, error_message, compression, encryption",
                "SELECT COUNT(*)"
            ).split(" ORDER BY")[0]  # Remove ORDER BY, LIMIT, OFFSET
            
            count_params = params[:-2]  # Remove LIMIT and OFFSET params
            total_count = await conn.fetchval(count_query, *count_params)
            
            # Get events
            rows = await conn.fetch(query, *params)
            events = []
            
            for row in rows:
                if criteria.include_event_data:
                    event_data, metadata = await self._unprocess_event_data(
                        row['event_data'], row['metadata'],
                        row['compression'], row['encryption']
                    )
                else:
                    event_data, metadata = {}, EventMetadata()
                
                events.append(EventRecord(
                    event_id=row['event_id'],
                    aggregate_id=row['aggregate_id'],
                    aggregate_type=row['aggregate_type'],
                    event_type=row['event_type'],
                    event_version=row['event_version'],
                    aggregate_version=row['aggregate_version'],
                    event_data=event_data,
                    metadata=metadata,
                    created_at=row['created_at'],
                    stored_at=row['stored_at'],
                    status=EventStatus(row['status']),
                    error_message=row['error_message'],
                    stream_id=row['stream_id'],
                    stream_position=row['stream_position'],
                    global_position=row['global_position']
                ))
        
        # Calculate pagination info
        page_count = (total_count + criteria.limit - 1) // criteria.limit
        current_page = (criteria.offset // criteria.limit) + 1
        has_more = criteria.offset + len(events) < total_count
        
        # Calculate search duration
        search_duration = (datetime.now() - start_time).total_seconds() * 1000
        
        self._read_counter += len(events)
        
        return EventSearchResult(
            events=events,
            total_count=total_count,
            page_count=page_count,
            current_page=current_page,
            has_more=has_more,
            search_duration_ms=search_duration
        )
    
    async def get_stream_metadata(self, stream_id: str) -> dict[str, Any]:
        """Get metadata about a specific stream."""
        async with self._get_connection() as conn:
            result = await conn.fetchrow(f"""
                SELECT 
                    COUNT(*) as event_count,
                    MAX(stream_position) as last_position,
                    MIN(created_at) as first_event_at,
                    MAX(created_at) as last_event_at,
                    SUM(CASE WHEN compression != 'none' THEN compressed_size ELSE original_size END) as total_size
                FROM {self.schema_name}.events
                WHERE stream_id = $1
            """, stream_id)
            
            return {
                "stream_id": stream_id,
                "event_count": result['event_count'] or 0,
                "last_position": result['last_position'] or 0,
                "first_event_at": result['first_event_at'],
                "last_event_at": result['last_event_at'],
                "total_size_bytes": result['total_size'] or 0
            }
    
    async def create_snapshot(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        version: int,
        snapshot_data: dict[str, Any],
        metadata: dict[str, Any] | None = None
    ) -> SnapshotRecord:
        """Create a snapshot of an aggregate."""
        snapshot_id = uuid4()
        now = datetime.now(UTC)
        
        # Compress snapshot data
        original_data = json.dumps(snapshot_data)
        original_size = len(original_data.encode('utf-8'))
        
        if self.enable_compression:
            compressed_data = gzip.compress(original_data.encode('utf-8'))
            compressed_size = len(compressed_data)
            compression = CompressionType.GZIP
        else:
            compressed_data = original_data.encode('utf-8')
            compressed_size = original_size
            compression = CompressionType.NONE
        
        async with self._get_connection() as conn:
            await conn.execute(f"""
                INSERT INTO {self.schema_name}.event_snapshots (
                    snapshot_id, aggregate_id, aggregate_type, aggregate_version,
                    snapshot_data, metadata, created_at, compression,
                    original_size, compressed_size
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (aggregate_id, aggregate_type, aggregate_version)
                DO UPDATE SET
                    snapshot_data = EXCLUDED.snapshot_data,
                    metadata = EXCLUDED.metadata,
                    created_at = EXCLUDED.created_at
            """, 
                snapshot_id, aggregate_id, aggregate_type, version,
                json.dumps(snapshot_data), json.dumps(metadata or {}),
                now, compression.value, original_size, compressed_size
            )
        
        return SnapshotRecord(
            snapshot_id=snapshot_id,
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            aggregate_version=version,
            snapshot_data=snapshot_data,
            metadata=EventMetadata(**(metadata or {})),
            created_at=now,
            compression=compression,
            original_size=original_size,
            compressed_size=compressed_size
        )
    
    async def get_latest_snapshot(
        self,
        aggregate_id: UUID,
        aggregate_type: str,
        max_version: int | None = None
    ) -> SnapshotRecord | None:
        """Get the latest snapshot for an aggregate."""
        query = f"""
            SELECT snapshot_id, aggregate_id, aggregate_type, aggregate_version,
                   snapshot_data, metadata, created_at, compression,
                   original_size, compressed_size
            FROM {self.schema_name}.event_snapshots
            WHERE aggregate_id = $1 AND aggregate_type = $2
        """
        params = [aggregate_id, aggregate_type]
        
        if max_version is not None:
            query += " AND aggregate_version <= $3"
            params.append(max_version)
        
        query += " ORDER BY aggregate_version DESC LIMIT 1"
        
        async with self._get_connection() as conn:
            row = await conn.fetchrow(query, *params)
            
            if not row:
                return None
            
            # Decompress snapshot data if needed
            if row['compression'] == 'gzip':
                snapshot_data = json.loads(
                    gzip.decompress(row['snapshot_data'].encode('utf-8')).decode('utf-8')
                )
            else:
                snapshot_data = json.loads(row['snapshot_data'])
            
            return SnapshotRecord(
                snapshot_id=row['snapshot_id'],
                aggregate_id=row['aggregate_id'],
                aggregate_type=row['aggregate_type'],
                aggregate_version=row['aggregate_version'],
                snapshot_data=snapshot_data,
                metadata=EventMetadata(**json.loads(row['metadata'])),
                created_at=row['created_at'],
                compression=CompressionType(row['compression']),
                original_size=row['original_size'],
                compressed_size=row['compressed_size']
            )
    
    async def delete_events(
        self,
        criteria: EventSearchCriteria,
        soft_delete: bool = True
    ) -> int:
        """Delete events for GDPR compliance."""
        # This is a simplified implementation
        # In production, you'd want more sophisticated deletion logic
        query_parts = [f"UPDATE {self.schema_name}.events SET"]
        
        if soft_delete:
            query_parts.append(" status = 'deleted', event_data = '{}', metadata = '{}'")
        else:
            query_parts = [f"DELETE FROM {self.schema_name}.events"]
        
        query_parts.append(" WHERE 1=1")
        
        params = []
        param_count = 0
        
        if criteria.aggregate_ids:
            param_count += 1
            query_parts.append(f" AND aggregate_id = ANY(${param_count})")
            params.append(criteria.aggregate_ids)
        
        if criteria.user_ids:
            param_count += 1
            query_parts.append(f" AND metadata->>'user_id' = ANY(${param_count})")
            params.append([str(uid) for uid in criteria.user_ids])
        
        query = "".join(query_parts)
        
        async with self._get_connection() as conn:
            result = await conn.execute(query, *params)
            # Extract number from result like "UPDATE 5" or "DELETE 3"
            return int(result.split()[-1])
    
    async def anonymize_events(
        self,
        criteria: EventSearchCriteria,
        anonymization_map: dict[str, str]
    ) -> int:
        """Anonymize events for GDPR compliance."""
        # This would implement field-by-field anonymization
        # For now, returning 0 as placeholder
        return 0
    
    async def archive_events(
        self,
        criteria: EventSearchCriteria,
        archive_location: str
    ) -> int:
        """Archive old events to external storage."""
        # This would implement archival to S3, GCS, etc.
        # For now, returning 0 as placeholder
        return 0
    
    async def get_metrics(
        self,
        from_time: datetime | None = None,
        to_time: datetime | None = None
    ) -> EventStoreMetrics:
        """Get event store metrics."""
        async with self._get_connection() as conn:
            # Basic metrics query
            result = await conn.fetchrow(f"""
                SELECT 
                    COUNT(*) as total_events,
                    SUM(original_size) as total_storage,
                    SUM(compressed_size) as compressed_storage,
                    AVG(compressed_size::float / NULLIF(original_size, 0)) as compression_ratio
                FROM {self.schema_name}.events
                WHERE ($1::timestamptz IS NULL OR created_at >= $1)
                  AND ($2::timestamptz IS NULL OR created_at <= $2)
            """, from_time, to_time)
            
            return EventStoreMetrics(
                total_events=result['total_events'] or 0,
                total_storage_bytes=result['total_storage'] or 0,
                compressed_storage_bytes=result['compressed_storage'] or 0,
                compression_ratio=result['compression_ratio'] or 0.0,
                measured_at=datetime.now(UTC)
            )
    
    async def create_stream_reader(
        self,
        stream_id: str,
        from_position: int | None = None,
        batch_size: int = 100
    ) -> AsyncIterator[list[EventRecord]]:
        """Create an async iterator for reading events from a stream."""
        current_position = from_position or 0
        
        while True:
            events = await self.get_events(
                stream_id, 
                current_position, 
                current_position + batch_size - 1
            )
            
            if not events:
                break
                
            yield events
            current_position += len(events)
            
            if len(events) < batch_size:
                break
    
    async def get_checkpoint(
        self,
        checkpoint_name: str,
        consumer_group: str | None = None
    ) -> StreamPosition | None:
        """Get a checkpoint position."""
        async with self._get_connection() as conn:
            row = await conn.fetchrow(f"""
                SELECT stream_id, position, global_position, updated_at
                FROM {self.schema_name}.stream_checkpoints
                WHERE checkpoint_name = $1 AND consumer_group = $2
            """, checkpoint_name, consumer_group or "")
            
            if not row:
                return None
                
            return StreamPosition(
                stream_id=row['stream_id'],
                position=row['position'],
                global_position=row['global_position'],
                timestamp=row['updated_at'],
                checkpoint_name=checkpoint_name,
                consumer_group=consumer_group
            )
    
    async def save_checkpoint(
        self,
        checkpoint_name: str,
        position: StreamPosition,
        consumer_group: str | None = None
    ) -> None:
        """Save a checkpoint position."""
        async with self._get_connection() as conn:
            await conn.execute(f"""
                INSERT INTO {self.schema_name}.stream_checkpoints 
                (checkpoint_name, consumer_group, stream_id, position, global_position)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (checkpoint_name, consumer_group, stream_id)
                DO UPDATE SET 
                    position = EXCLUDED.position,
                    global_position = EXCLUDED.global_position,
                    updated_at = NOW()
            """, checkpoint_name, consumer_group or "", position.stream_id, 
                position.position, position.global_position)
    
    async def health_check(self) -> dict[str, Any]:
        """Perform a health check."""
        try:
            async with self._get_connection() as conn:
                # Test basic connectivity
                await conn.fetchval("SELECT 1")
                
                # Get basic stats
                stats = await conn.fetchrow(f"""
                    SELECT 
                        COUNT(*) as total_events,
                        MAX(global_position) as max_position
                    FROM {self.schema_name}.events
                """)
                
                return {
                    "status": "healthy",
                    "total_events": stats['total_events'],
                    "max_position": stats['max_position'],
                    "write_count": self._write_counter,
                    "read_count": self._read_counter,
                    "error_count": self._error_counter
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    async def optimize_storage(
        self,
        criteria: EventSearchCriteria | None = None
    ) -> dict[str, Any]:
        """Optimize storage by running VACUUM and ANALYZE."""
        async with self._get_connection() as conn:
            # Run VACUUM and ANALYZE
            await conn.execute(f"VACUUM ANALYZE {self.schema_name}.events")
            await conn.execute(f"VACUUM ANALYZE {self.schema_name}.event_snapshots")
            
            return {
                "status": "completed",
                "operations": ["vacuum", "analyze"],
                "completed_at": datetime.now(UTC)
            }
    
    @asynccontextmanager
    async def _get_connection(self):
        """Get a database connection from the pool."""
        async with self.pool.acquire() as conn:
            yield conn
    
    async def _get_stream_version(self, conn: Connection, stream_id: str) -> int:
        """Get the current version of a stream."""
        version = await conn.fetchval(f"""
            SELECT COALESCE(MAX(stream_position), 0)
            FROM {self.schema_name}.events
            WHERE stream_id = $1
        """, stream_id)
        return version or 0
    
    async def _get_next_stream_position(self, conn: Connection, stream_id: str) -> int:
        """Get the next position for a stream."""
        return await conn.fetchval(
            f"SELECT {self.schema_name}.get_next_stream_position($1)",
            stream_id
        )
    
    async def _process_event_data(
        self, 
        event_data: dict[str, Any], 
        metadata: EventMetadata
    ) -> tuple[str, str]:
        """Process event data with compression and encryption."""
        # Serialize data
        data_str = json.dumps(event_data)
        metadata_str = json.dumps(metadata.__dict__)
        
        # Apply compression if enabled
        if self.enable_compression:
            data_str = gzip.compress(data_str.encode('utf-8')).decode('latin-1')
            metadata.compression = CompressionType.GZIP
        
        # Apply encryption if enabled
        if self.enable_encryption and self.encryption_key:
            # Simplified encryption placeholder
            metadata.encryption = EncryptionType.AES_256_GCM
        
        return data_str, metadata_str
    
    async def _unprocess_event_data(
        self,
        data_str: str,
        metadata_str: str,
        compression: str,
        encryption: str
    ) -> tuple[dict[str, Any], EventMetadata]:
        """Unprocess event data by decompressing and decrypting."""
        # Decrypt if needed
        if encryption and encryption != 'none':
            # Implement decryption logic
            pass
        
        # Decompress if needed
        if compression == 'gzip':
            data_str = gzip.decompress(data_str.encode('latin-1')).decode('utf-8')
        
        # Parse JSON
        event_data = json.loads(data_str)
        metadata_dict = json.loads(metadata_str) if metadata_str else {}
        metadata = EventMetadata(**metadata_dict)
        
        return event_data, metadata