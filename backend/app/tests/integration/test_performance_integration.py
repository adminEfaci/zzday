"""
Performance Integration Tests

Tests system performance across module boundaries under various load conditions,
ensuring the system meets performance requirements in realistic scenarios.
"""

import asyncio
import statistics
import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.events.bus import InMemoryEventBus
from app.modules.audit.domain.events.audit_events import *
from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.entities.user.user_events import *
from app.modules.integration.domain.events.integration_events import *
from app.modules.notification.domain.events import *


@pytest.mark.integration
@pytest.mark.performance
class TestEventProcessingPerformance:
    """Test event processing performance across modules."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_high_volume_event_throughput(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        performance_tracker,
        user_factory,
    ):
        """Test system throughput with high volume of events."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Performance metrics tracking
        processed_events = []
        processing_times = []

        async def track_performance(event):
            processed_events.append(
                {
                    "type": type(event).__name__,
                    "timestamp": datetime.now(UTC),
                    "user_id": getattr(event, "user_id", None),
                }
            )

        # Subscribe to multiple event types
        event_types = [
            UserCreated,
            LoginSuccessful,
            PasswordChanged,
            AuditEntryRecorded,
            NotificationCreated,
        ]

        for event_type in event_types:
            event_bus.subscribe(event_type, track_performance)

        # Generate test users
        users = [user_factory() for _ in range(100)]

        # Test Configuration
        event_volume = 1000
        concurrent_batches = 10
        event_volume // concurrent_batches

        performance_tracker.start()

        async def process_event_batch(batch_users: list[User]) -> float:
            """Process a batch of events and return processing time."""
            batch_start = time.perf_counter()
            batch_tasks = []

            for user in batch_users:
                # Create multiple events per user
                events = [
                    UserCreated(
                        user_id=user.id,
                        email=user.email.value,
                        name=f"Perf Test User {user.id}",
                        role="user",
                        registration_method="bulk_test",
                        occurred_at=datetime.now(UTC),
                    ),
                    LoginSuccessful(
                        user_id=user.id,
                        session_id=uuid4(),
                        ip_address="192.168.1.100",
                        user_agent="Performance Test Client",
                        occurred_at=datetime.now(UTC),
                    ),
                    PasswordChanged(
                        user_id=user.id,
                        strength_score=0.8,
                        occurred_at=datetime.now(UTC),
                    ),
                ]

                for event in events:
                    batch_tasks.append(event_bus.publish(event))

            await asyncio.gather(*batch_tasks)
            batch_end = time.perf_counter()
            return batch_end - batch_start

        # Execute concurrent batches
        batch_tasks = []
        for i in range(concurrent_batches):
            start_idx = i * (len(users) // concurrent_batches)
            end_idx = (i + 1) * (len(users) // concurrent_batches)
            batch_users = users[start_idx:end_idx]
            batch_tasks.append(process_event_batch(batch_users))

        batch_times = await asyncio.gather(*batch_tasks)
        processing_times.extend(batch_times)

        # Wait for all events to be processed
        await asyncio.sleep(1.0)

        performance_tracker.stop()

        # PERFORMANCE ASSERTIONS

        # 1. Throughput Requirements
        total_time = performance_tracker.elapsed_time
        events_per_second = event_volume / total_time

        assert (
            events_per_second >= 100
        ), f"Throughput too low: {events_per_second:.2f} events/sec (required: ≥100)"

        # 2. Event Processing Completeness
        assert (
            len(processed_events) >= event_volume * 0.95
        ), f"Event loss detected: {len(processed_events)}/{event_volume}"

        # 3. Latency Requirements
        avg_batch_time = statistics.mean(batch_times)
        assert (
            avg_batch_time <= 1.0
        ), f"Average batch processing time too high: {avg_batch_time:.3f}s"

        # 4. Service Performance Under Load
        audit_call_count = mock_audit_service.create_audit_log.call_count
        assert (
            audit_call_count >= event_volume * 0.9
        ), f"Audit service performance degraded: {audit_call_count}/{event_volume}"

        # 5. No Memory Leaks (approximate check)
        unique_user_ids = {e["user_id"] for e in processed_events if e["user_id"]}
        assert len(unique_user_ids) <= len(users), "Memory/state leak suspected"

        performance_tracker.record_metric("events_per_second", events_per_second)
        performance_tracker.record_metric("avg_batch_time", avg_batch_time)
        performance_tracker.record_metric(
            "total_events_processed", len(processed_events)
        )

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_concurrent_user_operations_performance(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        user_factory,
        performance_tracker,
    ):
        """Test performance with concurrent user operations."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        concurrent_operations = []
        operation_timings = {}

        async def track_operation_timing(event):
            operation_type = type(event).__name__
            current_time = time.perf_counter()

            if operation_type not in operation_timings:
                operation_timings[operation_type] = []

            operation_timings[operation_type].append(current_time)
            concurrent_operations.append(
                {
                    "type": operation_type,
                    "timestamp": current_time,
                    "user_id": getattr(event, "user_id", None),
                }
            )

        # Subscribe to user operation events
        user_events = [
            UserCreated,
            LoginSuccessful,
            LoginFailed,
            PasswordChanged,
            ProfileUpdated,
            MFAEnabled,
        ]

        for event_type in user_events:
            event_bus.subscribe(event_type, track_operation_timing)

        # Create multiple users for concurrent operations
        users = [user_factory() for _ in range(50)]

        performance_tracker.start()

        async def simulate_user_session(user: User):
            """Simulate a complete user session with multiple operations."""
            session_start = time.perf_counter()

            # User registration
            await event_bus.publish(
                UserCreated(
                    user_id=user.id,
                    email=user.email.value,
                    name=f"Concurrent User {user.id}",
                    role="user",
                    registration_method="concurrent_test",
                    occurred_at=datetime.now(UTC),
                )
            )

            # Failed login attempt
            await event_bus.publish(
                LoginFailed(
                    email=user.email.value,
                    ip_address="192.168.1.100",
                    user_agent="Test Client",
                    failure_reason="invalid_password",
                    risk_score=0.3,
                    user_id=user.id,
                    occurred_at=datetime.now(UTC),
                )
            )

            # Successful login
            await event_bus.publish(
                LoginSuccessful(
                    user_id=user.id,
                    session_id=uuid4(),
                    ip_address="192.168.1.100",
                    user_agent="Test Client",
                    mfa_used=False,
                    trusted_device=True,
                    occurred_at=datetime.now(UTC),
                )
            )

            # Profile update
            await event_bus.publish(
                ProfileUpdated(
                    user_id=user.id,
                    updated_fields=["preferences"],
                    previous_values={},
                    new_values={"preferences": {"theme": "dark"}},
                    occurred_at=datetime.now(UTC),
                )
            )

            # MFA setup
            await event_bus.publish(
                MFAEnabled(
                    user_id=user.id,
                    device_id=uuid4(),
                    device_type="app",
                    device_name="Auth App",
                    enabled_at=datetime.now(UTC),
                    backup_codes_generated=True,
                    occurred_at=datetime.now(UTC),
                )
            )

            # Password change
            await event_bus.publish(
                PasswordChanged(
                    user_id=user.id,
                    strength_score=0.9,
                    force_password_change=False,
                    occurred_at=datetime.now(UTC),
                )
            )

            session_end = time.perf_counter()
            return session_end - session_start

        # Execute all user sessions concurrently
        session_tasks = [simulate_user_session(user) for user in users]
        session_times = await asyncio.gather(*session_tasks)

        await asyncio.sleep(0.5)  # Allow final events to process

        performance_tracker.stop()

        # CONCURRENT PERFORMANCE ASSERTIONS

        # 1. Session Performance
        avg_session_time = statistics.mean(session_times)
        max_session_time = max(session_times)

        assert (
            avg_session_time <= 0.5
        ), f"Average session time too high: {avg_session_time:.3f}s"
        assert (
            max_session_time <= 1.0
        ), f"Maximum session time too high: {max_session_time:.3f}s"

        # 2. Operation Distribution
        expected_operations = len(users) * 6  # 6 operations per user
        assert (
            len(concurrent_operations) >= expected_operations * 0.95
        ), f"Operation loss detected: {len(concurrent_operations)}/{expected_operations}"

        # 3. Event Type Distribution
        for event_type in ["UserCreated", "LoginSuccessful", "PasswordChanged"]:
            event_count = len(
                [op for op in concurrent_operations if op["type"] == event_type]
            )
            assert (
                event_count >= len(users) * 0.9
            ), f"Insufficient {event_type} events: {event_count}/{len(users)}"

        # 4. Concurrent Processing Efficiency
        total_time = performance_tracker.elapsed_time
        operations_per_second = len(concurrent_operations) / total_time

        assert (
            operations_per_second >= 50
        ), f"Concurrent processing too slow: {operations_per_second:.2f} ops/sec"

        # 5. Resource Utilization
        unique_users = {op["user_id"] for op in concurrent_operations if op["user_id"]}
        assert len(unique_users) == len(users), "User operation distribution issue"

        performance_tracker.record_metric("avg_session_time", avg_session_time)
        performance_tracker.record_metric(
            "operations_per_second", operations_per_second
        )
        performance_tracker.record_metric("concurrent_users", len(users))

        await event_bus.stop()


@pytest.mark.integration
@pytest.mark.performance
class TestSystemScalabilityPerformance:
    """Test system scalability under increasing load."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_load_scaling_performance(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        user_factory,
        performance_tracker,
    ):
        """Test system performance under increasing load."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        scaling_results = []

        async def track_scaling_events(event):
            pass  # Minimal tracking to reduce overhead

        event_bus.subscribe(UserCreated, track_scaling_events)
        event_bus.subscribe(LoginSuccessful, track_scaling_events)

        # Test different load levels
        load_levels = [10, 50, 100, 200, 500]

        for load_level in load_levels:
            users = [user_factory() for _ in range(load_level)]

            performance_tracker.start()

            # Generate load
            tasks = []
            for user in users:
                # Create registration event
                tasks.append(
                    event_bus.publish(
                        UserCreated(
                            user_id=user.id,
                            email=user.email.value,
                            name=f"Scale Test User {user.id}",
                            role="user",
                            registration_method="scale_test",
                            occurred_at=datetime.now(UTC),
                        )
                    )
                )

                # Create login event
                tasks.append(
                    event_bus.publish(
                        LoginSuccessful(
                            user_id=user.id,
                            session_id=uuid4(),
                            ip_address="192.168.1.100",
                            user_agent="Scale Test Client",
                            occurred_at=datetime.now(UTC),
                        )
                    )
                )

            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1)  # Allow processing

            performance_tracker.stop()

            events_processed = load_level * 2  # 2 events per user
            throughput = events_processed / performance_tracker.elapsed_time

            scaling_results.append(
                {
                    "load_level": load_level,
                    "processing_time": performance_tracker.elapsed_time,
                    "throughput": throughput,
                    "events_processed": events_processed,
                }
            )

            # Reset performance tracker
            performance_tracker.__init__()

        # SCALABILITY ASSERTIONS

        # 1. Linear Scaling Verification
        throughputs = [result["throughput"] for result in scaling_results]

        # Throughput should not degrade significantly with load
        min_throughput = min(throughputs)
        max_throughput = max(throughputs)
        throughput_degradation = (max_throughput - min_throughput) / max_throughput

        assert (
            throughput_degradation <= 0.5
        ), f"Excessive throughput degradation: {throughput_degradation:.2%}"

        # 2. Processing Time Scaling
        processing_times = [result["processing_time"] for result in scaling_results]

        # Processing time should scale sub-linearly
        for i in range(1, len(processing_times)):
            time_increase = processing_times[i] / processing_times[0]
            load_increase = load_levels[i] / load_levels[0]

            assert (
                time_increase <= load_increase * 1.5
            ), f"Poor time scaling at load {load_levels[i]}: {time_increase:.2f}x time for {load_increase:.2f}x load"

        # 3. Minimum Performance Thresholds
        for result in scaling_results:
            assert (
                result["throughput"] >= 20
            ), f"Throughput below threshold at load {result['load_level']}: {result['throughput']:.2f}"

        # 4. Memory/Resource Efficiency
        largest_load_result = scaling_results[-1]
        assert (
            largest_load_result["processing_time"] <= 10.0
        ), f"Maximum load processing time too high: {largest_load_result['processing_time']:.3f}s"

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_burst_traffic_handling(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        user_factory,
        performance_tracker,
    ):
        """Test system handling of burst traffic patterns."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        burst_metrics = []

        async def track_burst_events(event):
            burst_metrics.append(
                {"timestamp": time.perf_counter(), "type": type(event).__name__}
            )

        event_bus.subscribe(LoginSuccessful, track_burst_events)
        event_bus.subscribe(LoginFailed, track_burst_events)

        # Simulate burst traffic pattern
        users = [user_factory() for _ in range(100)]

        performance_tracker.start()

        # Normal load period
        normal_tasks = []
        for i in range(20):
            user = users[i]
            normal_tasks.append(
                event_bus.publish(
                    LoginSuccessful(
                        user_id=user.id,
                        session_id=uuid4(),
                        ip_address="192.168.1.100",
                        user_agent="Normal Client",
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

        await asyncio.gather(*normal_tasks)
        await asyncio.sleep(0.1)

        normal_load_end = time.perf_counter()

        # BURST PERIOD - High traffic spike
        burst_tasks = []
        for i in range(20, 100):
            user = users[i]
            # Mix of successful and failed logins to simulate real burst
            if i % 3 == 0:
                event = LoginFailed(
                    email=user.email.value,
                    ip_address="203.0.113.100",
                    user_agent="Burst Client",
                    failure_reason="invalid_password",
                    risk_score=0.5,
                    user_id=user.id,
                    occurred_at=datetime.now(UTC),
                )
            else:
                event = LoginSuccessful(
                    user_id=user.id,
                    session_id=uuid4(),
                    ip_address="192.168.1.100",
                    user_agent="Burst Client",
                    occurred_at=datetime.now(UTC),
                )

            burst_tasks.append(event_bus.publish(event))

        burst_start = time.perf_counter()
        await asyncio.gather(*burst_tasks)
        await asyncio.sleep(0.2)
        burst_end = time.perf_counter()

        # Recovery period
        recovery_tasks = []
        for i in range(10):
            user = users[i]
            recovery_tasks.append(
                event_bus.publish(
                    LoginSuccessful(
                        user_id=user.id,
                        session_id=uuid4(),
                        ip_address="192.168.1.100",
                        user_agent="Recovery Client",
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

        await asyncio.gather(*recovery_tasks)
        await asyncio.sleep(0.1)

        performance_tracker.stop()

        # BURST HANDLING ASSERTIONS

        # 1. Event Processing Completeness
        assert (
            len(burst_metrics) >= 110
        ), f"Event loss during burst: {len(burst_metrics)}/110 expected"

        # 2. Burst Response Time
        burst_duration = burst_end - burst_start
        burst_events = 80  # Events in burst period
        burst_throughput = burst_events / burst_duration

        assert (
            burst_throughput >= 50
        ), f"Burst throughput too low: {burst_throughput:.2f} events/sec"

        # 3. System Recovery
        recovery_events = [e for e in burst_metrics if e["timestamp"] > burst_end]
        assert len(recovery_events) >= 10, "System didn't recover properly"

        # 4. No System Degradation
        normal_events = [e for e in burst_metrics if e["timestamp"] < normal_load_end]

        # System should handle normal load efficiently
        assert len(normal_events) >= 20, "Normal load processing degraded"

        # 5. Event Type Distribution During Burst
        burst_period_events = [
            e for e in burst_metrics if burst_start <= e["timestamp"] <= burst_end
        ]

        successful_logins = [
            e for e in burst_period_events if e["type"] == "LoginSuccessful"
        ]
        failed_logins = [e for e in burst_period_events if e["type"] == "LoginFailed"]

        assert len(successful_logins) >= 50, "Successful login processing degraded"
        assert len(failed_logins) >= 25, "Failed login processing degraded"

        await event_bus.stop()


@pytest.mark.integration
@pytest.mark.performance
class TestDatabasePerformanceIntegration:
    """Test database performance across module operations."""

    @pytest.mark.asyncio
    async def test_concurrent_database_operations_performance(
        self, mock_audit_service: AsyncMock, user_factory, performance_tracker
    ):
        """Test database performance with concurrent operations."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Mock database operation timing
        db_operation_times = []

        async def mock_db_operation():
            """Simulate database operation with realistic timing."""
            start_time = time.perf_counter()
            await asyncio.sleep(0.01)  # Simulate DB query time
            end_time = time.perf_counter()
            db_operation_times.append(end_time - start_time)

        # Configure mock to track DB performance
        mock_audit_service.create_audit_log.side_effect = (
            lambda *args, **kwargs: asyncio.create_task(mock_db_operation())
        )

        db_events = []

        async def track_db_events(event):
            db_events.append(
                {
                    "type": type(event).__name__,
                    "timestamp": time.perf_counter(),
                    "user_id": getattr(event, "user_id", None),
                }
            )

        event_bus.subscribe(UserCreated, track_db_events)
        event_bus.subscribe(LoginSuccessful, track_db_events)

        users = [user_factory() for _ in range(50)]

        performance_tracker.start()

        # Concurrent database operations
        db_tasks = []
        for user in users:
            # Events that trigger database operations
            db_tasks.append(
                event_bus.publish(
                    UserCreated(
                        user_id=user.id,
                        email=user.email.value,
                        name=f"DB Test User {user.id}",
                        role="user",
                        registration_method="db_test",
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

            db_tasks.append(
                event_bus.publish(
                    LoginSuccessful(
                        user_id=user.id,
                        session_id=uuid4(),
                        ip_address="192.168.1.100",
                        user_agent="DB Test Client",
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

        await asyncio.gather(*db_tasks)
        await asyncio.sleep(0.5)  # Allow DB operations to complete

        performance_tracker.stop()

        # DATABASE PERFORMANCE ASSERTIONS

        # 1. Database Operation Completion
        assert (
            len(db_operation_times) >= 100
        ), f"Missing DB operations: {len(db_operation_times)}/100"

        # 2. Database Response Time
        avg_db_time = statistics.mean(db_operation_times)
        max_db_time = max(db_operation_times)

        assert (
            avg_db_time <= 0.05
        ), f"Average DB operation time too high: {avg_db_time:.3f}s"
        assert (
            max_db_time <= 0.1
        ), f"Maximum DB operation time too high: {max_db_time:.3f}s"

        # 3. Concurrent DB Operation Efficiency
        total_db_time = sum(db_operation_times)
        actual_time = performance_tracker.elapsed_time
        parallelization_efficiency = total_db_time / actual_time

        assert (
            parallelization_efficiency >= 2.0
        ), f"Poor DB parallelization: {parallelization_efficiency:.2f}x"

        # 4. Event Processing with DB Load
        assert (
            len(db_events) >= 100
        ), f"Event processing degraded under DB load: {len(db_events)}/100"

        # 5. No Database Bottlenecks
        db_time_variance = statistics.variance(db_operation_times)
        assert (
            db_time_variance <= 0.001
        ), f"High DB operation time variance: {db_time_variance:.6f}"

        await event_bus.stop()


@pytest.mark.integration
@pytest.mark.performance
class TestMemoryAndResourcePerformance:
    """Test memory usage and resource performance."""

    @pytest.mark.asyncio
    async def test_memory_efficiency_under_load(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        user_factory,
        performance_tracker,
    ):
        """Test memory efficiency under sustained load."""

        import os

        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        event_bus = InMemoryEventBus()
        await event_bus.start()

        memory_measurements = []
        processed_events = []

        async def track_memory_usage(event):
            processed_events.append(event)
            if len(processed_events) % 100 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_measurements.append(
                    {
                        "events_processed": len(processed_events),
                        "memory_mb": current_memory,
                        "memory_increase": current_memory - initial_memory,
                    }
                )

        event_bus.subscribe(UserCreated, track_memory_usage)
        event_bus.subscribe(LoginSuccessful, track_memory_usage)
        event_bus.subscribe(PasswordChanged, track_memory_usage)

        # Sustained load test
        performance_tracker.start()

        total_events = 1000
        users = [user_factory() for _ in range(total_events // 3)]

        # Generate sustained load
        for i in range(0, len(users), 10):  # Process in batches
            batch_tasks = []
            batch_users = users[i : i + 10]

            for user in batch_users:
                # Multiple events per user
                events = [
                    UserCreated(
                        user_id=user.id,
                        email=user.email.value,
                        name=f"Memory Test User {user.id}",
                        role="user",
                        registration_method="memory_test",
                        occurred_at=datetime.now(UTC),
                    ),
                    LoginSuccessful(
                        user_id=user.id,
                        session_id=uuid4(),
                        ip_address="192.168.1.100",
                        user_agent="Memory Test Client",
                        occurred_at=datetime.now(UTC),
                    ),
                    PasswordChanged(
                        user_id=user.id,
                        strength_score=0.8,
                        occurred_at=datetime.now(UTC),
                    ),
                ]

                for event in events:
                    batch_tasks.append(event_bus.publish(event))

            await asyncio.gather(*batch_tasks)
            await asyncio.sleep(0.05)  # Small delay between batches

        # Final processing time
        await asyncio.sleep(0.5)

        performance_tracker.stop()

        final_memory = process.memory_info().rss / 1024 / 1024
        total_memory_increase = final_memory - initial_memory

        # MEMORY EFFICIENCY ASSERTIONS

        # 1. Memory Growth Rate
        events_per_mb = len(processed_events) / max(total_memory_increase, 1)
        assert (
            events_per_mb >= 1000
        ), f"Poor memory efficiency: {events_per_mb:.2f} events/MB"

        # 2. Linear Memory Growth
        if len(memory_measurements) >= 3:
            memory_increases = [m["memory_increase"] for m in memory_measurements]
            event_counts = [m["events_processed"] for m in memory_measurements]

            # Check for linear relationship (no memory leaks)
            for i in range(1, len(memory_measurements)):
                memory_ratio = memory_increases[i] / max(memory_increases[0], 1)
                event_ratio = event_counts[i] / event_counts[0]

                assert (
                    memory_ratio <= event_ratio * 1.5
                ), f"Memory leak detected: {memory_ratio:.2f}x memory for {event_ratio:.2f}x events"

        # 3. Absolute Memory Limits
        assert (
            total_memory_increase <= 100
        ), f"Excessive memory usage: {total_memory_increase:.2f} MB increase"

        # 4. Event Processing Completeness
        assert (
            len(processed_events) >= total_events * 0.95
        ), f"Event loss under memory pressure: {len(processed_events)}/{total_events}"

        # 5. Processing Efficiency
        events_per_second = len(processed_events) / performance_tracker.elapsed_time
        assert (
            events_per_second >= 100
        ), f"Processing efficiency degraded: {events_per_second:.2f} events/sec"

        performance_tracker.record_metric(
            "memory_efficiency_events_per_mb", events_per_mb
        )
        performance_tracker.record_metric(
            "total_memory_increase_mb", total_memory_increase
        )
        performance_tracker.record_metric("events_processed", len(processed_events))

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_resource_cleanup_performance(
        self, mock_audit_service: AsyncMock, user_factory, performance_tracker
    ):
        """Test resource cleanup and garbage collection performance."""

        import gc

        event_bus = InMemoryEventBus()
        await event_bus.start()

        cleanup_metrics = []

        async def track_cleanup_events(event):
            # Force garbage collection periodically
            if len(cleanup_metrics) % 50 == 0:
                gc_start = time.perf_counter()
                collected = gc.collect()
                gc_end = time.perf_counter()

                cleanup_metrics.append(
                    {
                        "gc_time": gc_end - gc_start,
                        "objects_collected": collected,
                        "events_processed": len(cleanup_metrics),
                    }
                )

        event_bus.subscribe(UserCreated, track_cleanup_events)

        users = [user_factory() for _ in range(200)]

        performance_tracker.start()

        # Create and process many events to test cleanup
        for user in users:
            await event_bus.publish(
                UserCreated(
                    user_id=user.id,
                    email=user.email.value,
                    name=f"Cleanup Test User {user.id}",
                    role="user",
                    registration_method="cleanup_test",
                    occurred_at=datetime.now(UTC),
                )
            )

            # Periodically yield control
            if len(cleanup_metrics) % 25 == 0:
                await asyncio.sleep(0.01)

        # Final cleanup
        await asyncio.sleep(0.2)
        final_gc_start = time.perf_counter()
        final_collected = gc.collect()
        final_gc_end = time.perf_counter()

        performance_tracker.stop()

        # RESOURCE CLEANUP ASSERTIONS

        # 1. Garbage Collection Efficiency
        if cleanup_metrics:
            avg_gc_time = statistics.mean([m["gc_time"] for m in cleanup_metrics])
            assert avg_gc_time <= 0.01, f"GC time too high: {avg_gc_time:.4f}s"

        # 2. Object Collection
        total_collected = sum(m["objects_collected"] for m in cleanup_metrics)
        total_collected += final_collected

        # Should collect some objects, indicating proper cleanup
        assert (
            total_collected >= 10
        ), f"Insufficient object collection: {total_collected}"

        # 3. Final Cleanup Performance
        final_gc_time = final_gc_end - final_gc_start
        assert final_gc_time <= 0.05, f"Final cleanup too slow: {final_gc_time:.4f}s"

        # 4. System Responsiveness During Cleanup
        total_gc_time = sum(m["gc_time"] for m in cleanup_metrics) + final_gc_time
        gc_overhead = total_gc_time / performance_tracker.elapsed_time

        assert gc_overhead <= 0.1, f"Excessive GC overhead: {gc_overhead:.2%}"

        await event_bus.stop()
