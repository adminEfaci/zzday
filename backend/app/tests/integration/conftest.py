"""
Integration Test Configuration

Specific configuration and fixtures for integration testing across modules.
Provides comprehensive test infrastructure for cross-module testing scenarios.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from app.core.events.bus import InMemoryEventBus
from app.modules.identity.domain.value_objects.email import Email


@pytest.fixture
def integration_event_bus():
    """Create an event bus specifically for integration testing."""
    return InMemoryEventBus()


@pytest.fixture
async def started_event_bus(integration_event_bus: InMemoryEventBus):
    """Create and start an event bus for integration tests."""
    await integration_event_bus.start()
    yield integration_event_bus
    await integration_event_bus.stop()


@pytest.fixture
def comprehensive_mock_audit_service():
    """Comprehensive mock audit service for integration testing."""
    mock = AsyncMock()

    # Standard audit operations
    mock.create_audit_log.return_value = {
        "id": str(uuid4()),
        "status": "created",
        "timestamp": datetime.now(UTC),
    }

    mock.create_security_audit.return_value = {
        "id": str(uuid4()),
        "risk_level": "medium",
        "status": "created",
    }

    mock.update_audit_log.return_value = {"id": str(uuid4()), "status": "updated"}

    mock.get_audit_trail.return_value = []
    mock.search_audit_entries.return_value = {
        "entries": [],
        "total_count": 0,
        "page": 1,
    }

    # Performance tracking
    mock._call_count = 0
    mock._performance_metrics = []

    def track_performance(*args, **kwargs):
        mock._call_count += 1
        mock._performance_metrics.append(
            {"call_time": datetime.now(UTC), "args": args, "kwargs": kwargs}
        )
        return {"id": str(uuid4()), "status": "tracked"}

    mock.create_audit_log.side_effect = track_performance
    mock.create_security_audit.side_effect = track_performance

    return mock


@pytest.fixture
def comprehensive_mock_notification_service():
    """Comprehensive mock notification service for integration testing."""
    mock = AsyncMock()

    # Email notifications
    mock.send_welcome_email.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "delivery_method": "email",
    }

    mock.send_verification_email.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "verification_token": "token_123",
    }

    mock.send_password_reset_email.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "reset_token": "reset_456",
    }

    # Security notifications
    mock.send_security_alert.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "alert_type": "security",
    }

    mock.send_account_lockout_alert.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "alert_type": "lockout",
    }

    # Admin notifications
    mock.send_admin_alert.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "recipient": "admin",
    }

    mock.send_emergency_alert.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "priority": "emergency",
    }

    # Status notifications
    mock.send_status_update_notification.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "notification_type": "status_update",
    }

    mock.send_account_status_notification.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "notification_type": "account_status",
    }

    # GDPR/Compliance notifications
    mock.send_dpo_notification.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "recipient": "dpo",
    }

    mock.send_data_export_notification.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "export_id": str(uuid4()),
    }

    mock.send_deletion_confirmation.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "confirmation_type": "deletion",
    }

    # Multi-channel notifications
    mock.send_sms_notification.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "delivery_method": "sms",
    }

    mock.send_push_notification.return_value = {
        "message_id": str(uuid4()),
        "status": "sent",
        "delivery_method": "push",
    }

    # Batch notifications
    mock.send_batch_notifications.return_value = {
        "batch_id": str(uuid4()),
        "status": "processing",
        "total_recipients": 0,
    }

    # Notification tracking
    mock._notification_count = 0
    mock._sent_notifications = []

    def track_notification(*args, **kwargs):
        mock._notification_count += 1
        notification = {
            "id": str(uuid4()),
            "timestamp": datetime.now(UTC),
            "args": args,
            "kwargs": kwargs,
        }
        mock._sent_notifications.append(notification)
        return notification

    # Apply tracking to key methods
    for method_name in [
        "send_welcome_email",
        "send_security_alert",
        "send_admin_alert",
    ]:
        getattr(mock, method_name).side_effect = track_notification

    return mock


@pytest.fixture
def comprehensive_mock_integration_service():
    """Comprehensive mock integration service for integration testing."""
    mock = AsyncMock()

    # Webhook operations
    mock.trigger_webhooks.return_value = {
        "webhooks_triggered": 1,
        "successful_deliveries": 1,
        "failed_deliveries": 0,
        "delivery_id": str(uuid4()),
    }

    mock.process_webhook.return_value = {
        "webhook_id": str(uuid4()),
        "status": "processed",
        "processing_time_ms": 120.5,
        "actions_taken": ["update_user", "send_notification"],
    }

    mock.retry_failed_webhook.return_value = {
        "webhook_id": str(uuid4()),
        "retry_attempt": 1,
        "status": "retrying",
    }

    # Integration management
    mock.connect_integration.return_value = {
        "integration_id": str(uuid4()),
        "status": "connected",
        "capabilities": ["webhooks", "data_sync"],
    }

    mock.disconnect_integration.return_value = {
        "integration_id": str(uuid4()),
        "status": "disconnected",
        "cleanup_completed": True,
    }

    mock.check_integration_health.return_value = {
        "integration_id": str(uuid4()),
        "status": "healthy",
        "response_time_ms": 45.2,
        "last_check": datetime.now(UTC).isoformat(),
    }

    # Data synchronization
    mock.sync_user_data.return_value = {
        "sync_id": str(uuid4()),
        "status": "completed",
        "records_synced": 1,
    }

    mock.bulk_sync_data.return_value = {
        "sync_id": str(uuid4()),
        "status": "processing",
        "total_records": 100,
    }

    # External API operations
    mock.call_external_api.return_value = {
        "api_call_id": str(uuid4()),
        "status": "success",
        "response_code": 200,
    }

    # Integration tracking
    mock._webhook_count = 0
    mock._triggered_webhooks = []

    def track_webhook(*args, **kwargs):
        mock._webhook_count += 1
        webhook = {
            "id": str(uuid4()),
            "timestamp": datetime.now(UTC),
            "event_type": kwargs.get("event_type", "unknown"),
            "args": args,
            "kwargs": kwargs,
        }
        mock._triggered_webhooks.append(webhook)
        return {
            "webhooks_triggered": 1,
            "successful_deliveries": 1,
            "webhook_id": webhook["id"],
        }

    mock.trigger_webhooks.side_effect = track_webhook

    return mock


@pytest.fixture
def integration_test_users(user_factory):
    """Create a set of test users for integration testing."""
    return [
        user_factory(
            email=Email("integration.test.1@example.com"),
            is_active=True,
            is_verified=True,
        ),
        user_factory(
            email=Email("integration.test.2@example.com"),
            is_active=False,
            is_verified=False,
        ),
        user_factory(
            email=Email("integration.admin@example.com"),
            is_active=True,
            is_verified=True,
            is_admin=True,
        ),
    ]


@pytest.fixture
def integration_performance_tracker():
    """Performance tracker specifically for integration tests."""
    import time

    class IntegrationPerformanceTracker:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.metrics = {}
            self.checkpoints = []

        def start(self):
            self.start_time = time.perf_counter()
            self.checkpoints = []

        def checkpoint(self, name: str):
            current_time = time.perf_counter()
            if self.start_time:
                elapsed = current_time - self.start_time
                self.checkpoints.append(
                    {"name": name, "elapsed_time": elapsed, "timestamp": current_time}
                )

        def stop(self):
            self.end_time = time.perf_counter()
            return self.elapsed_time

        @property
        def elapsed_time(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

        def record_metric(self, name: str, value: float):
            self.metrics[name] = value

        def assert_performance(self, max_seconds: float, message: str | None = None):
            elapsed = self.elapsed_time
            if message is None:
                message = f"Performance test failed: {elapsed:.3f}s > {max_seconds}s"
            assert elapsed <= max_seconds, message

        def assert_checkpoint_performance(
            self, checkpoint_name: str, max_seconds: float
        ):
            checkpoint = next(
                (cp for cp in self.checkpoints if cp["name"] == checkpoint_name), None
            )
            assert checkpoint is not None, f"Checkpoint '{checkpoint_name}' not found"
            assert (
                checkpoint["elapsed_time"] <= max_seconds
            ), f"Checkpoint '{checkpoint_name}' too slow: {checkpoint['elapsed_time']:.3f}s > {max_seconds}s"

        def get_summary(self) -> dict[str, Any]:
            return {
                "total_time": self.elapsed_time,
                "checkpoints": self.checkpoints,
                "metrics": self.metrics,
                "checkpoint_count": len(self.checkpoints),
            }

    return IntegrationPerformanceTracker()


@pytest.fixture
def integration_event_tracker():
    """Comprehensive event tracker for integration tests."""

    class IntegrationEventTracker:
        def __init__(self):
            self.events = []
            self.event_counts = {}
            self.user_events = {}
            self.timeline = []

        async def track_event(self, event):
            event_type = type(event).__name__
            user_id = getattr(event, "user_id", None)
            timestamp = getattr(event, "occurred_at", datetime.now(UTC))

            event_data = {
                "type": event_type,
                "user_id": user_id,
                "timestamp": timestamp,
                "event": event,
            }

            self.events.append(event_data)
            self.timeline.append(event_data)

            # Update counts
            self.event_counts[event_type] = self.event_counts.get(event_type, 0) + 1

            # Track by user
            if user_id:
                if user_id not in self.user_events:
                    self.user_events[user_id] = []
                self.user_events[user_id].append(event_data)

        def get_events_by_type(self, event_type: str) -> list[dict[str, Any]]:
            return [e for e in self.events if e["type"] == event_type]

        def get_events_by_user(self, user_id: UUID) -> list[dict[str, Any]]:
            return self.user_events.get(user_id, [])

        def get_event_count(self, event_type: str) -> int:
            return self.event_counts.get(event_type, 0)

        def get_timeline_for_user(self, user_id: UUID) -> list[dict[str, Any]]:
            user_timeline = [e for e in self.timeline if e["user_id"] == user_id]
            return sorted(user_timeline, key=lambda x: x["timestamp"])

        def assert_event_sequence(
            self, expected_sequence: list[str], user_id: UUID | None = None
        ):
            if user_id:
                timeline = self.get_timeline_for_user(user_id)
            else:
                timeline = sorted(self.timeline, key=lambda x: x["timestamp"])

            actual_sequence = [event["type"] for event in timeline]

            # Check if expected sequence is a subsequence of actual sequence
            expected_index = 0
            for event_type in actual_sequence:
                if (
                    expected_index < len(expected_sequence)
                    and event_type == expected_sequence[expected_index]
                ):
                    expected_index += 1

            assert expected_index == len(
                expected_sequence
            ), f"Event sequence mismatch. Expected: {expected_sequence}, Got: {actual_sequence}"

        def assert_event_count(self, event_type: str, expected_count: int):
            actual_count = self.get_event_count(event_type)
            assert (
                actual_count == expected_count
            ), f"Event count mismatch for {event_type}. Expected: {expected_count}, Got: {actual_count}"

        def assert_minimum_event_count(self, event_type: str, minimum_count: int):
            actual_count = self.get_event_count(event_type)
            assert (
                actual_count >= minimum_count
            ), f"Insufficient events for {event_type}. Expected: ≥{minimum_count}, Got: {actual_count}"

        def get_summary(self) -> dict[str, Any]:
            return {
                "total_events": len(self.events),
                "event_counts": self.event_counts,
                "unique_users": len(self.user_events),
                "event_types": list(self.event_counts.keys()),
            }

    return IntegrationEventTracker()


@pytest.fixture
def integration_scenario_runner():
    """Runner for complex integration scenarios."""

    class IntegrationScenarioRunner:
        def __init__(self):
            self.scenarios = {}
            self.results = {}

        def register_scenario(self, name: str, scenario_func):
            self.scenarios[name] = scenario_func

        async def run_scenario(self, name: str, *args, **kwargs):
            if name not in self.scenarios:
                raise ValueError(f"Scenario '{name}' not registered")

            start_time = datetime.now(UTC)
            try:
                result = await self.scenarios[name](*args, **kwargs)
                status = "success"
                error = None
            except Exception as e:
                result = None
                status = "failed"
                error = str(e)

            end_time = datetime.now(UTC)

            self.results[name] = {
                "status": status,
                "result": result,
                "error": error,
                "start_time": start_time,
                "end_time": end_time,
                "duration": (end_time - start_time).total_seconds(),
            }

            if status == "failed":
                raise Exception(f"Scenario '{name}' failed: {error}")

            return result

        async def run_all_scenarios(self, *args, **kwargs):
            results = {}
            for name in self.scenarios:
                try:
                    results[name] = await self.run_scenario(name, *args, **kwargs)
                except Exception as e:
                    results[name] = {"error": str(e)}
            return results

        def get_scenario_result(self, name: str):
            return self.results.get(name)

        def assert_scenario_success(self, name: str):
            result = self.results.get(name)
            assert result is not None, f"Scenario '{name}' was not run"
            assert (
                result["status"] == "success"
            ), f"Scenario '{name}' failed: {result.get('error', 'Unknown error')}"

        def assert_all_scenarios_successful(self):
            for name, result in self.results.items():
                assert (
                    result["status"] == "success"
                ), f"Scenario '{name}' failed: {result.get('error', 'Unknown error')}"

    return IntegrationScenarioRunner()


@pytest.fixture
def integration_test_config():
    """Configuration for integration tests."""
    return {
        "event_processing_timeout": 0.5,
        "performance_threshold_seconds": 2.0,
        "max_event_processing_time": 1.0,
        "expected_audit_coverage": 0.95,
        "expected_notification_delivery": 0.98,
        "expected_webhook_success_rate": 0.90,
        "concurrent_user_limit": 100,
        "event_volume_limit": 1000,
        "memory_limit_mb": 500,
        "test_timeout_seconds": 30,
    }


# Pytest configuration for integration tests
def pytest_configure(config):
    """Configure pytest for integration tests."""
    config.addinivalue_line(
        "markers", "integration_slow: mark test as slow integration test"
    )
    config.addinivalue_line(
        "markers", "integration_performance: mark test as performance integration test"
    )
    config.addinivalue_line(
        "markers", "integration_e2e: mark test as end-to-end integration test"
    )


@pytest.fixture(autouse=True)
async def integration_test_cleanup():
    """Automatically cleanup after integration tests."""
    yield

    # Cleanup any remaining event bus instances
    import gc

    gc.collect()

    # Small delay to ensure all async operations complete
    await asyncio.sleep(0.01)
