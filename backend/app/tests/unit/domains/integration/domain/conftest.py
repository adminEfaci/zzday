"""
Integration Domain Layer Test Configuration

Provides fixtures and utilities for testing Integration domain layer components.
Includes factories for aggregates, entities, value objects, and events.
"""

import secrets
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from app.modules.integration.domain.aggregates.integration import Integration
from app.modules.integration.domain.aggregates.webhook_endpoint import WebhookEndpoint
from app.modules.integration.domain.entities.api_credential import ApiCredential
from app.modules.integration.domain.entities.integration_mapping import (
    IntegrationMapping,
)
from app.modules.integration.domain.entities.sync_job import SyncJob
from app.modules.integration.domain.entities.webhook_event import WebhookEvent
from app.modules.integration.domain.enums import (
    AuthType,
    IntegrationType,
    SignatureAlgorithm,
    SyncDirection,
    WebhookMethod,
    WebhookStatus,
)
from app.modules.integration.domain.value_objects.api_endpoint import ApiEndpoint
from app.modules.integration.domain.value_objects.auth_method import AuthMethod
from app.modules.integration.domain.value_objects.rate_limit_config import (
    RateLimitConfig,
)
from app.modules.integration.domain.value_objects.webhook_signature import (
    WebhookSignature,
)


@pytest.fixture
def integration_id() -> UUID:
    """Generate an integration ID."""
    return uuid4()


@pytest.fixture
def user_id() -> UUID:
    """Generate a user ID."""
    return uuid4()


@pytest.fixture
def api_endpoint() -> ApiEndpoint:
    """Create a basic API endpoint."""
    return ApiEndpoint(
        base_url="https://api.example.com", version="v1", timeout_seconds=30
    )


@pytest.fixture
def auth_method() -> AuthMethod:
    """Create a basic auth method."""
    return AuthMethod(
        auth_type=AuthType.API_KEY,
        auth_config={"header_name": "X-API-Key", "location": "header"},
    )


@pytest.fixture
def rate_limit_config() -> RateLimitConfig:
    """Create a basic rate limit configuration."""
    return RateLimitConfig(
        requests_per_minute=100, requests_per_hour=5000, burst_limit=10
    )


@pytest.fixture
def webhook_signature() -> WebhookSignature:
    """Create a webhook signature configuration."""
    return WebhookSignature(
        algorithm=SignatureAlgorithm.HMAC_SHA256,
        secret=secrets.token_urlsafe(32),
        header_name="X-Webhook-Signature",
    )


@pytest.fixture
def basic_integration(
    integration_id: UUID, user_id: UUID, api_endpoint: ApiEndpoint
) -> Integration:
    """Create a basic integration."""
    return Integration(
        name="Test Integration",
        integration_type=IntegrationType.REST_API,
        system_name="TestSystem",
        api_endpoint=api_endpoint,
        owner_id=user_id,
        description="Test integration for unit tests",
        entity_id=integration_id,
    )


@pytest.fixture
def webhook_endpoint(
    integration_id: UUID, webhook_signature: WebhookSignature
) -> WebhookEndpoint:
    """Create a basic webhook endpoint."""
    return WebhookEndpoint(
        integration_id=integration_id,
        name="Test Webhook",
        path="/webhook",
        signature_config=webhook_signature,
        allowed_events=["user.created", "user.updated"],
        allowed_methods=[WebhookMethod.POST],
        is_active=True,
    )


@pytest.fixture
def api_credential(integration_id: UUID) -> ApiCredential:
    """Create a basic API credential."""
    return ApiCredential(
        integration_id=integration_id,
        name="Test Credential",
        credential_type=AuthType.API_KEY,
        encrypted_data=b"encrypted_api_key_data",
        is_active=True,
    )


@pytest.fixture
def webhook_event(
    integration_id: UUID, webhook_endpoint: WebhookEndpoint
) -> WebhookEvent:
    """Create a basic webhook event."""
    return WebhookEvent(
        endpoint_id=webhook_endpoint.id,
        integration_id=integration_id,
        event_type="user.created",
        payload={"user_id": str(uuid4()), "action": "created"},
        headers={"Content-Type": "application/json"},
        method=WebhookMethod.POST,
        source_ip="192.168.1.100",
        signature="test_signature",
        is_valid_signature=True,
        status=WebhookStatus.PENDING,
    )


@pytest.fixture
def integration_mapping(integration_id: UUID) -> IntegrationMapping:
    """Create a basic integration mapping."""
    return IntegrationMapping(
        integration_id=integration_id,
        name="User Mapping",
        description="Maps user fields",
        source_entity="User",
        target_entity="ExternalUser",
        field_mappings={
            "id": "external_id",
            "email": "email_address",
            "name": "display_name",
        },
        transformation_rules={"email": "lowercase", "name": "trim"},
        is_active=True,
    )


@pytest.fixture
def sync_job(integration_id: UUID) -> SyncJob:
    """Create a basic sync job."""
    return SyncJob(
        integration_id=integration_id,
        name="User Sync",
        description="Synchronize user data",
        direction=SyncDirection.BIDIRECTIONAL,
        entity_type="User",
        schedule_config={"type": "interval", "interval_minutes": 60},
        is_active=True,
    )


@pytest.fixture
def integration_factory():
    """Factory for creating Integration instances."""

    def _factory(
        name: str | None = None,
        integration_type: IntegrationType = None,
        system_name: str | None = None,
        owner_id: UUID | None = None,
        entity_id: UUID | None = None,
        **kwargs,
    ) -> Integration:
        return Integration(
            name=name or f"Integration {uuid4().hex[:8]}",
            integration_type=integration_type or IntegrationType.REST_API,
            system_name=system_name or f"System {uuid4().hex[:6]}",
            api_endpoint=kwargs.get("api_endpoint")
            or ApiEndpoint(base_url="https://api.example.com", version="v1"),
            owner_id=owner_id or uuid4(),
            entity_id=entity_id,
            **kwargs,
        )

    return _factory


@pytest.fixture
def webhook_endpoint_factory():
    """Factory for creating WebhookEndpoint instances."""

    def _factory(
        integration_id: UUID | None = None,
        name: str | None = None,
        path: str | None = None,
        entity_id: UUID | None = None,
        **kwargs,
    ) -> WebhookEndpoint:
        return WebhookEndpoint(
            integration_id=integration_id or uuid4(),
            name=name or f"Webhook {uuid4().hex[:8]}",
            path=path or f"/webhook/{uuid4().hex[:8]}",
            entity_id=entity_id,
            **kwargs,
        )

    return _factory


@pytest.fixture
def api_credential_factory():
    """Factory for creating ApiCredential instances."""

    def _factory(
        integration_id: UUID | None = None,
        name: str | None = None,
        credential_type: AuthType = None,
        entity_id: UUID | None = None,
        **kwargs,
    ) -> ApiCredential:
        return ApiCredential(
            integration_id=integration_id or uuid4(),
            name=name or f"Credential {uuid4().hex[:8]}",
            credential_type=credential_type or AuthType.API_KEY,
            encrypted_data=kwargs.get("encrypted_data") or b"encrypted_test_data",
            entity_id=entity_id,
            **kwargs,
        )

    return _factory


@pytest.fixture
def webhook_event_factory():
    """Factory for creating WebhookEvent instances."""

    def _factory(
        endpoint_id: UUID | None = None,
        integration_id: UUID | None = None,
        event_type: str | None = None,
        entity_id: UUID | None = None,
        **kwargs,
    ) -> WebhookEvent:
        return WebhookEvent(
            endpoint_id=endpoint_id or uuid4(),
            integration_id=integration_id or uuid4(),
            event_type=event_type or "test.event",
            payload=kwargs.get("payload") or {"test": "data"},
            headers=kwargs.get("headers") or {"Content-Type": "application/json"},
            method=kwargs.get("method") or WebhookMethod.POST,
            source_ip=kwargs.get("source_ip") or "192.168.1.100",
            entity_id=entity_id,
            **kwargs,
        )

    return _factory


@pytest.fixture
def integration_test_data():
    """Provide comprehensive test data for integration tests."""
    return {
        "valid_configurations": [
            {
                "name": "Salesforce Integration",
                "type": IntegrationType.CRM,
                "system": "Salesforce",
                "capabilities": ["read", "write", "sync", "webhooks"],
            },
            {
                "name": "Slack Integration",
                "type": IntegrationType.COMMUNICATION,
                "system": "Slack",
                "capabilities": ["notifications", "webhooks"],
            },
            {
                "name": "Database Sync",
                "type": IntegrationType.DATABASE,
                "system": "PostgreSQL",
                "capabilities": ["read", "write", "bulk_operations"],
            },
        ],
        "webhook_test_payloads": [
            {
                "event_type": "user.created",
                "payload": {
                    "user": {
                        "id": "123",
                        "email": "test@example.com",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                },
                "headers": {
                    "Content-Type": "application/json",
                    "X-Event-Type": "user.created",
                },
            },
            {
                "event_type": "order.completed",
                "payload": {
                    "order": {"id": "order_456", "total": 99.99, "status": "completed"}
                },
                "headers": {
                    "Content-Type": "application/json",
                    "X-Event-Type": "order.completed",
                },
            },
        ],
        "error_scenarios": [
            {
                "error_type": "connection_timeout",
                "message": "Connection timed out after 30 seconds",
                "is_retryable": True,
            },
            {
                "error_type": "authentication_failed",
                "message": "Invalid API key",
                "is_retryable": False,
            },
            {
                "error_type": "rate_limit_exceeded",
                "message": "Rate limit exceeded",
                "is_retryable": True,
            },
        ],
    }


@pytest.fixture
def performance_test_config():
    """Configuration for performance tests."""
    return {
        "webhook_volume": 1000,
        "concurrent_connections": 50,
        "processing_timeout": 5.0,
        "memory_limit_mb": 100,
        "throughput_target": 200,  # events per second
    }


@pytest.fixture
def mock_external_system():
    """Mock external system for testing."""
    mock = MagicMock()

    # Configure common responses
    mock.health_check.return_value = {"status": "healthy", "response_time_ms": 45.2}

    mock.authenticate.return_value = {"success": True, "token": "mock_token_123"}

    mock.send_data.return_value = {"success": True, "records_processed": 1}

    mock.receive_data.return_value = {"success": True, "data": {"test": "data"}}

    return mock


@pytest.fixture
def integration_events_tracker():
    """Track integration events for testing."""

    class EventTracker:
        def __init__(self):
            self.events = []
            self.event_counts = {}

        def track(self, event):
            event_type = type(event).__name__
            self.events.append(
                {"type": event_type, "event": event, "timestamp": datetime.now(UTC)}
            )
            self.event_counts[event_type] = self.event_counts.get(event_type, 0) + 1

        def get_events(self, event_type: str | None = None):
            if event_type:
                return [e for e in self.events if e["type"] == event_type]
            return self.events

        def get_count(self, event_type: str) -> int:
            return self.event_counts.get(event_type, 0)

        def clear(self):
            self.events.clear()
            self.event_counts.clear()

    return EventTracker()


# Test data constants
VALID_API_ENDPOINTS = [
    "https://api.example.com/v1",
    "https://api.service.com/v2",
    "https://external-system.com/api",
]

VALID_WEBHOOK_PATHS = [
    "/webhook",
    "/hooks/user",
    "/api/webhooks/integration",
    "/events/receiver",
]

INVALID_INTEGRATION_NAMES = ["", "   ", "a" * 101, None]  # Too long

INVALID_SYSTEM_NAMES = ["", "   ", "a" * 51, None]  # Too long

VALID_EVENT_TYPES = [
    "user.created",
    "user.updated",
    "user.deleted",
    "order.created",
    "order.completed",
    "payment.processed",
]

WEBHOOK_TEST_IPS = ["192.168.1.100", "10.0.0.1", "203.0.113.1", "127.0.0.1"]
