"""
Example implementations and usage patterns for the event store infrastructure.

This module provides concrete examples of how to use the event store
components for different scenarios in the identity module.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import asyncpg

from .event_archiver import ArchivalPolicy, ArchivalStrategy, EventArchiver
from .event_query_service import EventQueryService
from .event_replay_service import EventReplayService, ReplayConfig
from .event_snapshot import EventSnapshot, SnapshotConfig, SnapshotStrategy
from .event_store import EventStore
from .event_stream_reader import EventStreamReader, StreamConfig, StreamReadMode
from .postgresql_event_store import PostgreSQLEventStore
from .schemas import EventMetadata, EventRecord, EventSearchCriteria


class UserEventStore:
    """
    Example implementation of a user-specific event store.
    
    Demonstrates how to use the event store infrastructure for
    user-related events with proper GDPR compliance.
    """
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.snapshot_service = EventSnapshot(
            event_store,
            SnapshotConfig(
                strategy=SnapshotStrategy.EVENT_COUNT,
                event_threshold=50
            )
        )
        self.query_service = EventQueryService(event_store)
        self.archiver = EventArchiver(event_store)
        
        # Set up GDPR compliant archival policy
        self._setup_gdpr_policy()
    
    def _setup_gdpr_policy(self) -> None:
        """Set up GDPR compliant archival policy for user events."""
        gdpr_policy = ArchivalPolicy(
            policy_name="user_gdpr_retention",
            description="GDPR compliant retention for user events",
            strategy=ArchivalStrategy.GDPR_BASED,
            gdpr_retention_days=2555,  # 7 years
            anonymize_before_archive=True,
            event_type_policies={
                "UserCreated": {"max_age_days": 2555},
                "UserUpdated": {"max_age_days": 365},
                "UserLoginAttempted": {"max_age_days": 90},
                "UserDeleted": {"max_age_days": 30}
            }
        )
        
        self.archiver.register_policy(gdpr_policy)
    
    async def store_user_event(
        self,
        user_id: UUID,
        event_type: str,
        event_data: dict,
        correlation_id: str | None = None
    ) -> None:
        """Store a user-related event."""
        event = EventRecord(
            event_id=uuid4(),
            aggregate_id=user_id,
            aggregate_type="User",
            event_type=event_type,
            event_version=1,
            aggregate_version=1,
            event_data=event_data,
            metadata=EventMetadata(
                correlation_id=correlation_id,
                user_id=user_id,
                gdpr_compliant=True
            ),
            created_at=datetime.now(UTC),
            stored_at=datetime.now(UTC)
        )
        
        stream_id = f"User-{user_id}"
        await self.event_store.append_events(stream_id, [event])
    
    async def get_user_timeline(
        self,
        user_id: UUID,
        from_date: datetime | None = None,
        to_date: datetime | None = None
    ) -> list[EventRecord]:
        """Get complete timeline of events for a user."""
        return await self.query_service.get_aggregate_timeline(
            user_id, "User", from_date, to_date
        )
    
    async def find_user_login_patterns(self, user_id: UUID) -> dict:
        """Analyze user login patterns."""
        criteria = EventSearchCriteria(
            aggregate_ids=[user_id],
            event_types=["UserLoginAttempted", "UserLoginSucceeded", "UserLoginFailed"],
            from_timestamp=datetime.now(UTC) - timedelta(days=30),
            limit=1000
        )
        
        result, metrics = await self.query_service.query_events(criteria)
        
        # Analyze patterns
        login_times = []
        success_count = 0
        failure_count = 0
        
        for event in result.events:
            login_times.append(event.created_at)
            if event.event_type == "UserLoginSucceeded":
                success_count += 1
            elif event.event_type == "UserLoginFailed":
                failure_count += 1
        
        return {
            "total_attempts": len(result.events),
            "success_count": success_count,
            "failure_count": failure_count,
            "success_rate": success_count / len(result.events) if result.events else 0,
            "most_active_hours": self._analyze_login_hours(login_times),
            "query_performance": {
                "duration_ms": metrics.query_duration_ms,
                "cache_hit": metrics.cache_hit
            }
        }
    
    async def cleanup_user_data_gdpr(self, user_id: UUID) -> dict:
        """Clean up user data for GDPR compliance."""
        return await self.archiver.cleanup_gdpr_data(user_id, anonymize=True)
    
    def _analyze_login_hours(self, login_times: list[datetime]) -> list[int]:
        """Analyze most active login hours."""
        hour_counts = {}
        for login_time in login_times:
            hour = login_time.hour
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        # Return top 3 most active hours
        return sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)[:3]


class SecurityEventStore:
    """
    Example implementation for security-related events.
    
    Demonstrates high-frequency event handling with performance
    optimizations and real-time monitoring capabilities.
    """
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.query_service = EventQueryService(event_store)
        self.replay_service = EventReplayService(event_store)
        
        # Register security event handlers
        self._setup_security_handlers()
    
    def _setup_security_handlers(self) -> None:
        """Set up handlers for security event processing."""
        self.replay_service.register_event_handler(
            "SuspiciousActivity",
            self._handle_suspicious_activity
        )
        self.replay_service.register_event_handler(
            "SecurityBreach",
            self._handle_security_breach
        )
    
    async def store_security_event(
        self,
        event_type: str,
        event_data: dict,
        severity: str = "info",
        source_ip: str | None = None,
        user_id: UUID | None = None
    ) -> None:
        """Store a security-related event."""
        event = EventRecord(
            event_id=uuid4(),
            aggregate_id=uuid4(),  # Security events don't have a specific aggregate
            aggregate_type="SecurityLog",
            event_type=event_type,
            event_version=1,
            aggregate_version=1,
            event_data={
                **event_data,
                "severity": severity,
                "detected_at": datetime.now(UTC).isoformat()
            },
            metadata=EventMetadata(
                user_id=user_id,
                ip_address=source_ip,
                gdpr_compliant=True
            ),
            created_at=datetime.now(UTC),
            stored_at=datetime.now(UTC)
        )
        
        stream_id = f"SecurityLog-{datetime.now(UTC).strftime('%Y-%m-%d')}"
        await self.event_store.append_events(stream_id, [event])
    
    async def detect_anomalies(self) -> list[EventRecord]:
        """Detect anomalous security events."""
        return await self.query_service.find_anomalous_events(
            time_window_hours=1,
            threshold_multiplier=2.0
        )
    
    async def get_security_incidents(
        self, 
        severity: str = "high",
        hours: int = 24
    ) -> list[EventRecord]:
        """Get recent security incidents by severity."""
        from_time = datetime.now(UTC) - timedelta(hours=hours)
        
        events = await self.query_service.search_event_content(
            f'"severity": "{severity}"',
            event_types=["SuspiciousActivity", "SecurityBreach", "UnauthorizedAccess"]
        )
        
        return [e for e in events if e.created_at >= from_time]
    
    async def replay_security_incidents(self, hours: int = 24) -> dict:
        """Replay recent security incidents for analysis."""
        config = ReplayConfig(
            from_timestamp=datetime.now(UTC) - timedelta(hours=hours),
            event_types=["SuspiciousActivity", "SecurityBreach"],
            batch_size=50,
            dry_run=False
        )
        
        result = await self.replay_service.replay_events(config)
        
        return {
            "events_processed": result.total_events_processed,
            "incidents_found": result.successful_events,
            "duration_seconds": result.duration_seconds,
            "processing_rate": result.events_per_second
        }
    
    def _handle_suspicious_activity(self, event: EventRecord) -> None:
        """Handle suspicious activity events."""
        # In a real implementation, this would trigger alerts
        print(f"ALERT: Suspicious activity detected - {event.event_type}")
        print(f"Event ID: {event.event_id}")
        print(f"Data: {event.event_data}")
    
    def _handle_security_breach(self, event: EventRecord) -> None:
        """Handle security breach events."""
        # In a real implementation, this would trigger emergency protocols
        print(f"CRITICAL: Security breach detected - {event.event_type}")
        print(f"Event ID: {event.event_id}")
        print("Immediate action required!")


class AuditEventStore:
    """
    Example implementation for audit trail events.
    
    Demonstrates comprehensive audit capabilities with detailed
    tracking and compliance reporting.
    """
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.query_service = EventQueryService(event_store)
        self.archiver = EventArchiver(event_store)
        
        # Set up audit-specific archival policy
        self._setup_audit_policy()
    
    def _setup_audit_policy(self) -> None:
        """Set up audit trail archival policy."""
        audit_policy = ArchivalPolicy(
            policy_name="audit_trail_retention",
            description="Long-term retention for audit trail",
            strategy=ArchivalStrategy.TIME_BASED,
            max_age_days=2555,  # 7 years for compliance
            compress_archives=True,
            encrypt_archives=True
        )
        
        self.archiver.register_policy(audit_policy)
    
    async def create_audit_entry(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        user_id: UUID,
        changes: dict | None = None,
        ip_address: str | None = None
    ) -> None:
        """Create a comprehensive audit trail entry."""
        event = EventRecord(
            event_id=uuid4(),
            aggregate_id=UUID(resource_id) if resource_id else uuid4(),
            aggregate_type=resource_type,
            event_type=f"{resource_type}{action}",
            event_version=1,
            aggregate_version=1,
            event_data={
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "changes": changes or {},
                "timestamp": datetime.now(UTC).isoformat()
            },
            metadata=EventMetadata(
                user_id=user_id,
                ip_address=ip_address,
                gdpr_compliant=True,
                retention_until=datetime.now(UTC) + timedelta(days=2555)
            ),
            created_at=datetime.now(UTC),
            stored_at=datetime.now(UTC)
        )
        
        stream_id = f"AuditTrail-{resource_type}"
        await self.event_store.append_events(stream_id, [event])
    
    async def generate_compliance_report(
        self,
        from_date: datetime,
        to_date: datetime,
        user_id: UUID | None = None
    ) -> dict:
        """Generate a compliance audit report."""
        criteria = EventSearchCriteria(
            from_timestamp=from_date,
            to_timestamp=to_date,
            user_ids=[user_id] if user_id else None,
            limit=10000
        )
        
        result, metrics = await self.query_service.query_events(criteria)
        
        # Analyze audit events
        actions_by_type = {}
        users_activity = {}
        resources_modified = set()
        
        for event in result.events:
            action = event.event_data.get("action", "unknown")
            actions_by_type[action] = actions_by_type.get(action, 0) + 1
            
            user_id_str = str(event.metadata.user_id) if event.metadata.user_id else "system"
            users_activity[user_id_str] = users_activity.get(user_id_str, 0) + 1
            
            resource_id = event.event_data.get("resource_id")
            if resource_id:
                resources_modified.add(resource_id)
        
        return {
            "report_period": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat()
            },
            "summary": {
                "total_events": len(result.events),
                "unique_users": len(users_activity),
                "resources_modified": len(resources_modified),
                "most_common_actions": sorted(
                    actions_by_type.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:10]
            },
            "user_activity": users_activity,
            "query_performance": {
                "duration_ms": metrics.query_duration_ms,
                "total_matched": metrics.total_matched
            }
        }


async def example_usage():
    """
    Example of how to set up and use the event store infrastructure.
    """
    # Set up database connection pool
    DATABASE_URL = "postgresql://user:password@localhost/eventstore"
    pool = await asyncpg.create_pool(DATABASE_URL)
    
    # Initialize event store
    event_store = PostgreSQLEventStore(
        connection_pool=pool,
        schema_name="events",
        enable_compression=True,
        enable_encryption=False
    )
    
    # Initialize the database schema
    await event_store.initialize_schema()
    
    # Create domain-specific event stores
    user_store = UserEventStore(event_store)
    security_store = SecurityEventStore(event_store)
    audit_store = AuditEventStore(event_store)
    
    # Example: Store user events
    user_id = uuid4()
    await user_store.store_user_event(
        user_id=user_id,
        event_type="UserCreated",
        event_data={
            "email": "user@example.com",
            "name": "John Doe"
        },
        correlation_id="user-registration-flow"
    )
    
    # Example: Store security events
    await security_store.store_security_event(
        event_type="SuspiciousActivity",
        event_data={
            "activity_type": "multiple_failed_logins",
            "attempts": 5
        },
        severity="high",
        source_ip="192.168.1.100",
        user_id=user_id
    )
    
    # Example: Create audit trail
    await audit_store.create_audit_entry(
        action="Created",
        resource_type="User",
        resource_id=str(user_id),
        user_id=user_id,
        changes={"status": "active"},
        ip_address="192.168.1.100"
    )
    
    # Example: Query and analyze events
    user_timeline = await user_store.get_user_timeline(user_id)
    print(f"User has {len(user_timeline)} events in timeline")
    
    # Example: Generate compliance report
    report = await audit_store.generate_compliance_report(
        from_date=datetime.now(UTC) - timedelta(days=30),
        to_date=datetime.now(UTC)
    )
    print(f"Compliance report: {report['summary']}")
    
    # Example: Set up real-time event streaming
    stream_config = StreamConfig(
        consumer_group="user-analytics",
        read_mode=StreamReadMode.STREAMING,
        batch_size=50,
        event_types=["UserCreated", "UserUpdated", "UserDeleted"],
        event_handler=lambda event: print(f"Processing: {event.event_type}")
    )
    
    stream_reader = EventStreamReader(event_store, stream_config)
    
    # Process events for 10 seconds then stop
    async def stream_processing():
        await asyncio.sleep(10)
        await stream_reader.stop()
    
    # Run streaming in background
    processing_task = asyncio.create_task(stream_processing())
    metrics = await stream_reader.process_stream()
    
    print(f"Processed {metrics.events_processed} events")
    print(f"Processing rate: {metrics.processing_rate_per_second} events/sec")
    
    # Clean up
    await processing_task
    await pool.close()


if __name__ == "__main__":
    # Run the example
    asyncio.run(example_usage())