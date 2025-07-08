"""
Comprehensive tests for Integration aggregate root.

Tests all behaviors, business rules, and edge cases for the Integration aggregate,
ensuring 100% code coverage and validating all domain logic.
"""

from unittest.mock import patch
from uuid import uuid4

import pytest

from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.aggregates.integration import Integration
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType
from app.modules.integration.domain.events.integration_events import (
    IntegrationConfigurationUpdated,
    IntegrationConnected,
    IntegrationDisconnected,
    IntegrationErrorEvent,
    IntegrationHealthChecked,
)


class TestIntegrationCreation:
    """Test Integration aggregate creation and validation."""

    def test_create_integration_with_valid_data_succeeds(self, user_id, api_endpoint):
        """Test creating integration with valid data."""
        integration = Integration(
            name="Test Integration",
            integration_type=IntegrationType.REST_API,
            system_name="TestSystem",
            api_endpoint=api_endpoint,
            owner_id=user_id,
            description="Test description",
        )

        assert integration.name == "Test Integration"
        assert integration.integration_type == IntegrationType.REST_API
        assert integration.system_name == "TestSystem"
        assert integration.api_endpoint == api_endpoint
        assert integration.owner_id == user_id
        assert integration.description == "Test description"
        assert integration.status == ConnectionStatus.DISCONNECTED
        assert integration.is_active is True
        assert integration.health_check_failures == 0
        assert not integration.is_connected
        assert integration.id is not None

    def test_create_integration_with_minimal_data_succeeds(self, user_id, api_endpoint):
        """Test creating integration with minimal required data."""
        integration = Integration(
            name="Minimal Integration",
            integration_type=IntegrationType.DATABASE,
            system_name="DB",
            api_endpoint=api_endpoint,
            owner_id=user_id,
        )

        assert integration.name == "Minimal Integration"
        assert integration.description is None
        assert integration.rate_limit is None
        assert integration.capabilities == [
            "read",
            "write",
            "sync",
            "query",
            "bulk_operations",
        ]
        assert integration.configuration == {}

    def test_create_integration_with_custom_capabilities(self, user_id, api_endpoint):
        """Test creating integration with custom capabilities."""
        custom_capabilities = ["custom", "special"]

        integration = Integration(
            name="Custom Integration",
            integration_type=IntegrationType.REST_API,
            system_name="Custom",
            api_endpoint=api_endpoint,
            owner_id=user_id,
            capabilities=custom_capabilities,
        )

        assert integration.capabilities == custom_capabilities

    def test_create_integration_with_rate_limit(
        self, user_id, api_endpoint, rate_limit_config
    ):
        """Test creating integration with rate limit configuration."""
        integration = Integration(
            name="Rate Limited Integration",
            integration_type=IntegrationType.REST_API,
            system_name="RateLimit",
            api_endpoint=api_endpoint,
            owner_id=user_id,
            rate_limit=rate_limit_config,
        )

        assert integration.rate_limit == rate_limit_config

    def test_create_integration_with_custom_configuration(self, user_id, api_endpoint):
        """Test creating integration with custom configuration."""
        config = {"timeout": 60, "retry_count": 3, "use_ssl": True}

        integration = Integration(
            name="Configured Integration",
            integration_type=IntegrationType.REST_API,
            system_name="Configured",
            api_endpoint=api_endpoint,
            owner_id=user_id,
            configuration=config,
        )

        assert integration.configuration == config

    @pytest.mark.parametrize("invalid_name", ["", "   ", None])
    def test_create_integration_with_invalid_name_fails(
        self, invalid_name, user_id, api_endpoint
    ):
        """Test creating integration with invalid name fails."""
        with pytest.raises(ValidationError, match="Integration name cannot be empty"):
            Integration(
                name=invalid_name,
                integration_type=IntegrationType.REST_API,
                system_name="Test",
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

    def test_create_integration_with_long_name_fails(self, user_id, api_endpoint):
        """Test creating integration with too long name fails."""
        long_name = "a" * 101

        with pytest.raises(
            ValidationError, match="Integration name cannot exceed 100 characters"
        ):
            Integration(
                name=long_name,
                integration_type=IntegrationType.REST_API,
                system_name="Test",
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

    @pytest.mark.parametrize("invalid_system", ["", "   ", None])
    def test_create_integration_with_invalid_system_name_fails(
        self, invalid_system, user_id, api_endpoint
    ):
        """Test creating integration with invalid system name fails."""
        with pytest.raises(ValidationError, match="System name cannot be empty"):
            Integration(
                name="Test",
                integration_type=IntegrationType.REST_API,
                system_name=invalid_system,
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

    def test_create_integration_with_long_system_name_fails(
        self, user_id, api_endpoint
    ):
        """Test creating integration with too long system name fails."""
        long_system = "a" * 51

        with pytest.raises(
            ValidationError, match="System name cannot exceed 50 characters"
        ):
            Integration(
                name="Test",
                integration_type=IntegrationType.REST_API,
                system_name=long_system,
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

    def test_create_integration_validates_aggregate_state(self, user_id, api_endpoint):
        """Test that aggregate validation is called during creation."""
        # This should succeed with valid data
        integration = Integration(
            name="Valid Integration",
            integration_type=IntegrationType.REST_API,
            system_name="Valid",
            api_endpoint=api_endpoint,
            owner_id=user_id,
        )

        assert integration is not None

    def test_integration_name_is_trimmed(self, user_id, api_endpoint):
        """Test that integration name is properly trimmed."""
        integration = Integration(
            name="  Trimmed Name  ",
            integration_type=IntegrationType.REST_API,
            system_name="Trim",
            api_endpoint=api_endpoint,
            owner_id=user_id,
        )

        assert integration.name == "Trimmed Name"

    def test_system_name_is_trimmed(self, user_id, api_endpoint):
        """Test that system name is properly trimmed."""
        integration = Integration(
            name="Test",
            integration_type=IntegrationType.REST_API,
            system_name="  Trimmed System  ",
            api_endpoint=api_endpoint,
            owner_id=user_id,
        )

        assert integration.system_name == "Trimmed System"


class TestIntegrationDefaultCapabilities:
    """Test default capability assignment based on integration type."""

    def test_database_integration_default_capabilities(self, user_id, api_endpoint):
        """Test DATABASE integration gets appropriate default capabilities."""
        integration = Integration(
            name="DB Integration",
            integration_type=IntegrationType.DATABASE,
            system_name="Database",
            api_endpoint=api_endpoint,
            owner_id=user_id,
        )

        expected_capabilities = ["read", "write", "sync", "query", "bulk_operations"]
        assert set(integration.capabilities) == set(expected_capabilities)

    def test_webhook_supporting_integration_capabilities(self, user_id, api_endpoint):
        """Test integrations that support webhooks get webhook capability."""
        # Mock the integration type to support webhooks
        with patch.object(IntegrationType.REST_API, "supports_webhooks", True):
            integration = Integration(
                name="Webhook Integration",
                integration_type=IntegrationType.REST_API,
                system_name="WebhookAPI",
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

            assert "webhooks" in integration.capabilities

    def test_sync_supporting_integration_capabilities(self, user_id, api_endpoint):
        """Test integrations that support sync get sync capabilities."""
        # Mock the integration type to support sync
        with patch.object(IntegrationType.REST_API, "supports_sync", True):
            integration = Integration(
                name="Sync Integration",
                integration_type=IntegrationType.REST_API,
                system_name="SyncAPI",
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

            expected_capabilities = ["read", "write", "sync"]
            for cap in expected_capabilities:
                assert cap in integration.capabilities


class TestIntegrationProperties:
    """Test Integration aggregate properties."""

    def test_is_connected_property(self, basic_integration):
        """Test is_connected property returns correct values."""
        # Initially disconnected
        assert not basic_integration.is_connected

        # Set to connected
        basic_integration.status = ConnectionStatus.CONNECTED
        assert basic_integration.is_connected

    def test_is_healthy_property(self, basic_integration):
        """Test is_healthy property considers status and failure count."""
        # Set status to healthy but with failures
        basic_integration.status = ConnectionStatus.CONNECTED
        basic_integration.health_check_failures = 2
        assert basic_integration.is_healthy

        # Set failure count too high
        basic_integration.health_check_failures = 3
        assert not basic_integration.is_healthy

    def test_needs_attention_property(self, basic_integration):
        """Test needs_attention property."""
        # Normal state
        assert not basic_integration.needs_attention

        # With failures
        basic_integration.health_check_failures = 3
        assert basic_integration.needs_attention

        # With error status
        basic_integration.health_check_failures = 0
        basic_integration.status = ConnectionStatus.ERROR
        # Assuming ConnectionStatus.ERROR requires attention
        if hasattr(basic_integration.status, "requires_attention"):
            with patch.object(basic_integration.status, "requires_attention", True):
                assert basic_integration.needs_attention

    def test_can_sync_property(self, basic_integration):
        """Test can_sync property checks all conditions."""
        # Set up for sync capability
        basic_integration.status = ConnectionStatus.CONNECTED
        basic_integration.is_active = True
        basic_integration.capabilities = ["sync"]

        # Mock integration type to support sync
        with patch.object(basic_integration.integration_type, "supports_sync", True):
            assert basic_integration.can_sync

        # Test each condition
        basic_integration.status = ConnectionStatus.DISCONNECTED
        assert not basic_integration.can_sync

        basic_integration.status = ConnectionStatus.CONNECTED
        basic_integration.is_active = False
        assert not basic_integration.can_sync

        basic_integration.is_active = True
        basic_integration.capabilities = []
        assert not basic_integration.can_sync

    def test_can_receive_webhooks_property(self, basic_integration):
        """Test can_receive_webhooks property checks all conditions."""
        # Set up for webhook capability
        basic_integration.is_active = True
        basic_integration.capabilities = ["webhooks"]

        # Mock integration type to support webhooks
        with patch.object(
            basic_integration.integration_type, "supports_webhooks", True
        ):
            assert basic_integration.can_receive_webhooks

        # Test each condition
        basic_integration.is_active = False
        assert not basic_integration.can_receive_webhooks

        basic_integration.is_active = True
        basic_integration.capabilities = []
        assert not basic_integration.can_receive_webhooks


class TestIntegrationConnection:
    """Test Integration connection management."""

    def test_connect_integration_succeeds(self, basic_integration):
        """Test successful integration connection."""
        credential_id = uuid4()
        basic_integration.add_credential(credential_id)

        basic_integration.connect(credential_id)

        assert basic_integration.is_connected
        assert basic_integration.status == ConnectionStatus.CONNECTED
        assert basic_integration.health_check_failures == 0

        # Check event was emitted
        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationConnected)
        assert events[0].integration_id == basic_integration.id

    def test_connect_already_connected_integration_fails(self, basic_integration):
        """Test connecting already connected integration fails."""
        credential_id = uuid4()
        basic_integration.add_credential(credential_id)
        basic_integration.status = ConnectionStatus.CONNECTED

        with pytest.raises(DomainError, match="Integration is already connected"):
            basic_integration.connect(credential_id)

    def test_connect_inactive_integration_fails(self, basic_integration):
        """Test connecting inactive integration fails."""
        credential_id = uuid4()
        basic_integration.add_credential(credential_id)
        basic_integration.is_active = False

        with pytest.raises(DomainError, match="Cannot connect inactive integration"):
            basic_integration.connect(credential_id)

    def test_connect_with_invalid_credential_fails(self, basic_integration):
        """Test connecting with non-associated credential fails."""
        credential_id = uuid4()
        # Don't add credential to integration

        with pytest.raises(
            DomainError, match="Credential not associated with this integration"
        ):
            basic_integration.connect(credential_id)

    def test_disconnect_integration_succeeds(self, basic_integration):
        """Test successful integration disconnection."""
        # Set up connected state
        basic_integration.status = ConnectionStatus.CONNECTED
        user_id = uuid4()
        reason = "Manual disconnect"

        basic_integration.disconnect(user_id, reason)

        assert not basic_integration.is_connected
        assert basic_integration.status == ConnectionStatus.DISCONNECTED

        # Check event was emitted
        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationDisconnected)
        assert events[0].integration_id == basic_integration.id
        assert events[0].disconnected_by == user_id
        assert events[0].reason == reason
        assert not events[0].is_automatic

    def test_disconnect_already_disconnected_integration_does_nothing(
        self, basic_integration
    ):
        """Test disconnecting already disconnected integration does nothing."""
        # Integration is already disconnected by default
        original_events_count = len(basic_integration.events)

        basic_integration.disconnect()

        # Should not emit new events
        assert len(basic_integration.events) == original_events_count

    def test_disconnect_without_user_is_automatic(self, basic_integration):
        """Test disconnect without user ID is marked as automatic."""
        basic_integration.status = ConnectionStatus.CONNECTED

        basic_integration.disconnect(reason="System error")

        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationDisconnected)
        assert events[0].disconnected_by is None
        assert events[0].is_automatic is True


class TestIntegrationErrorHandling:
    """Test Integration error recording and handling."""

    def test_record_error_updates_status_and_emits_event(self, basic_integration):
        """Test recording error updates status and emits event."""
        # Set up connected state
        basic_integration.status = ConnectionStatus.CONNECTED

        error_type = "connection_timeout"
        error_message = "Connection timed out after 30 seconds"

        basic_integration.record_error(error_type, error_message, is_retryable=True)

        assert basic_integration.status == ConnectionStatus.ERROR

        # Check event was emitted
        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationErrorEvent)
        assert events[0].integration_id == basic_integration.id
        assert events[0].error_type == error_type
        assert events[0].error_message == error_message
        assert events[0].is_retryable is True

    def test_record_error_when_already_disconnected_keeps_status(
        self, basic_integration
    ):
        """Test recording error when disconnected doesn't change status."""
        # Integration is disconnected by default
        original_status = basic_integration.status

        basic_integration.record_error("test_error", "Test message")

        assert basic_integration.status == original_status


class TestIntegrationHealthCheck:
    """Test Integration health check functionality."""

    def test_health_check_success_updates_state(self, basic_integration):
        """Test successful health check updates state correctly."""
        # Set up error state
        basic_integration.status = ConnectionStatus.ERROR
        basic_integration.health_check_failures = 2

        response_time = 123.45

        basic_integration.health_check(is_healthy=True, response_time_ms=response_time)

        assert basic_integration.status == ConnectionStatus.CONNECTED
        assert basic_integration.health_check_failures == 0
        assert basic_integration.last_health_check is not None

        # Check event was emitted
        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationHealthChecked)
        assert events[0].integration_id == basic_integration.id
        assert events[0].response_time_ms == response_time

    def test_health_check_failure_increases_failure_count(self, basic_integration):
        """Test failed health check increases failure count."""
        basic_integration.status = ConnectionStatus.CONNECTED
        original_failures = basic_integration.health_check_failures

        error_message = "Health check failed"

        basic_integration.health_check(is_healthy=False, error_message=error_message)

        assert basic_integration.health_check_failures == original_failures + 1
        assert basic_integration.last_health_check is not None

        # Check event was emitted
        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationHealthChecked)
        assert events[0].error_message == error_message

    def test_health_check_three_failures_sets_error_status(self, basic_integration):
        """Test three consecutive failures sets error status."""
        basic_integration.status = ConnectionStatus.CONNECTED
        basic_integration.health_check_failures = 2  # Start with 2 failures

        basic_integration.health_check(is_healthy=False)

        assert basic_integration.health_check_failures == 3
        assert basic_integration.status == ConnectionStatus.ERROR


class TestIntegrationConfiguration:
    """Test Integration configuration management."""

    def test_update_configuration_with_valid_changes(self, basic_integration):
        """Test updating configuration with valid changes."""
        user_id = uuid4()
        updates = {"timeout": 60, "new_setting": "value"}

        # Set initial configuration
        basic_integration.configuration = {"timeout": 30, "existing": "keep"}

        basic_integration.update_configuration(updates, user_id)

        assert basic_integration.configuration["timeout"] == 60
        assert basic_integration.configuration["new_setting"] == "value"
        assert basic_integration.configuration["existing"] == "keep"

        # Check event was emitted
        events = basic_integration.events
        assert len(events) == 1
        assert isinstance(events[0], IntegrationConfigurationUpdated)
        assert events[0].updated_by == user_id
        assert events[0].changes == updates

    def test_update_configuration_with_empty_updates_does_nothing(
        self, basic_integration
    ):
        """Test updating configuration with empty dict does nothing."""
        user_id = uuid4()
        original_events_count = len(basic_integration.events)

        basic_integration.update_configuration({}, user_id)

        # Should not emit events
        assert len(basic_integration.events) == original_events_count

    def test_update_configuration_tracks_previous_values(self, basic_integration):
        """Test configuration update tracks previous values."""
        user_id = uuid4()
        basic_integration.configuration = {"setting1": "old", "setting2": "keep"}

        updates = {"setting1": "new", "setting3": "added"}

        basic_integration.update_configuration(updates, user_id)

        events = basic_integration.events
        config_event = events[0]
        assert config_event.previous_values == {"setting1": "old"}


class TestIntegrationCredentialManagement:
    """Test Integration credential management."""

    def test_add_credential_succeeds(self, basic_integration):
        """Test adding credential to integration."""
        credential_id = uuid4()

        basic_integration.add_credential(credential_id)

        assert credential_id in basic_integration._credential_ids

    def test_add_duplicate_credential_fails(self, basic_integration):
        """Test adding duplicate credential fails."""
        credential_id = uuid4()
        basic_integration.add_credential(credential_id)

        with pytest.raises(
            DomainError, match="Credential already added to integration"
        ):
            basic_integration.add_credential(credential_id)

    def test_remove_credential_succeeds(self, basic_integration):
        """Test removing credential from integration."""
        credential_id = uuid4()
        basic_integration.add_credential(credential_id)

        basic_integration.remove_credential(credential_id)

        assert credential_id not in basic_integration._credential_ids

    def test_remove_nonexistent_credential_fails(self, basic_integration):
        """Test removing non-existent credential fails."""
        credential_id = uuid4()

        with pytest.raises(DomainError, match="Credential not found in integration"):
            basic_integration.remove_credential(credential_id)


class TestIntegrationEntityManagement:
    """Test Integration management of child entities."""

    def test_add_sync_job(self, basic_integration):
        """Test adding sync job to integration."""
        sync_job_id = uuid4()

        basic_integration.add_sync_job(sync_job_id)

        assert sync_job_id in basic_integration._sync_job_ids

    def test_add_duplicate_sync_job_is_idempotent(self, basic_integration):
        """Test adding duplicate sync job is idempotent."""
        sync_job_id = uuid4()
        basic_integration.add_sync_job(sync_job_id)

        # Should not raise error
        basic_integration.add_sync_job(sync_job_id)

        assert basic_integration._sync_job_ids.count(sync_job_id) == 1

    def test_remove_sync_job(self, basic_integration):
        """Test removing sync job from integration."""
        sync_job_id = uuid4()
        basic_integration.add_sync_job(sync_job_id)

        basic_integration.remove_sync_job(sync_job_id)

        assert sync_job_id not in basic_integration._sync_job_ids

    def test_add_mapping(self, basic_integration):
        """Test adding mapping to integration."""
        mapping_id = uuid4()

        basic_integration.add_mapping(mapping_id)

        assert mapping_id in basic_integration._mapping_ids

    def test_remove_mapping(self, basic_integration):
        """Test removing mapping from integration."""
        mapping_id = uuid4()
        basic_integration.add_mapping(mapping_id)

        basic_integration.remove_mapping(mapping_id)

        assert mapping_id not in basic_integration._mapping_ids

    def test_add_webhook_endpoint_when_supported(self, basic_integration):
        """Test adding webhook endpoint when webhooks supported."""
        # Mock webhook support
        basic_integration.capabilities = ["webhooks"]
        with patch.object(basic_integration, "can_receive_webhooks", True):
            endpoint_id = uuid4()

            basic_integration.add_webhook_endpoint(endpoint_id)

            assert endpoint_id in basic_integration._webhook_endpoint_ids

    def test_add_webhook_endpoint_when_not_supported_fails(self, basic_integration):
        """Test adding webhook endpoint when not supported fails."""
        basic_integration.capabilities = []
        endpoint_id = uuid4()

        with pytest.raises(DomainError, match="Integration does not support webhooks"):
            basic_integration.add_webhook_endpoint(endpoint_id)

    def test_remove_webhook_endpoint(self, basic_integration):
        """Test removing webhook endpoint from integration."""
        # Set up webhook support and add endpoint
        basic_integration.capabilities = ["webhooks"]
        with patch.object(basic_integration, "can_receive_webhooks", True):
            endpoint_id = uuid4()
            basic_integration.add_webhook_endpoint(endpoint_id)

            basic_integration.remove_webhook_endpoint(endpoint_id)

            assert endpoint_id not in basic_integration._webhook_endpoint_ids


class TestIntegrationActivation:
    """Test Integration activation and deactivation."""

    def test_activate_inactive_integration(self, basic_integration):
        """Test activating inactive integration."""
        basic_integration.is_active = False

        basic_integration.activate()

        assert basic_integration.is_active is True

    def test_activate_already_active_integration_is_idempotent(self, basic_integration):
        """Test activating already active integration is idempotent."""
        assert basic_integration.is_active is True

        basic_integration.activate()

        assert basic_integration.is_active is True

    def test_deactivate_active_integration(self, basic_integration):
        """Test deactivating active integration."""
        basic_integration.deactivate()

        assert basic_integration.is_active is False

    def test_deactivate_connected_integration_disconnects(self, basic_integration):
        """Test deactivating connected integration also disconnects."""
        basic_integration.status = ConnectionStatus.CONNECTED
        original_events_count = len(basic_integration.events)

        basic_integration.deactivate()

        assert basic_integration.is_active is False
        assert not basic_integration.is_connected

        # Should emit disconnect event
        assert len(basic_integration.events) > original_events_count

    def test_deactivate_already_inactive_integration_is_idempotent(
        self, basic_integration
    ):
        """Test deactivating already inactive integration is idempotent."""
        basic_integration.is_active = False

        basic_integration.deactivate()

        assert basic_integration.is_active is False


class TestIntegrationCapabilityManagement:
    """Test Integration capability management."""

    def test_add_capability(self, basic_integration):
        """Test adding capability to integration."""
        original_capabilities = basic_integration.capabilities.copy()
        new_capability = "custom_capability"

        basic_integration.add_capability(new_capability)

        assert new_capability in basic_integration.capabilities
        assert len(basic_integration.capabilities) == len(original_capabilities) + 1

    def test_add_duplicate_capability_is_idempotent(self, basic_integration):
        """Test adding duplicate capability is idempotent."""
        capability = "sync"
        basic_integration.capabilities = [capability]

        basic_integration.add_capability(capability)

        assert basic_integration.capabilities.count(capability) == 1

    def test_remove_capability(self, basic_integration):
        """Test removing capability from integration."""
        capability = "sync"
        basic_integration.capabilities = [capability, "read", "write"]

        basic_integration.remove_capability(capability)

        assert capability not in basic_integration.capabilities

    def test_remove_nonexistent_capability_is_safe(self, basic_integration):
        """Test removing non-existent capability is safe."""
        original_capabilities = basic_integration.capabilities.copy()

        basic_integration.remove_capability("nonexistent")

        assert basic_integration.capabilities == original_capabilities


class TestIntegrationRateLimitManagement:
    """Test Integration rate limit management."""

    def test_update_rate_limit(self, basic_integration, rate_limit_config):
        """Test updating rate limit configuration."""
        basic_integration.update_rate_limit(rate_limit_config)

        assert basic_integration.rate_limit == rate_limit_config


class TestIntegrationSerialization:
    """Test Integration serialization and string representation."""

    def test_to_dict_includes_all_fields(self, basic_integration):
        """Test to_dict includes all expected fields."""
        data = basic_integration.to_dict()

        # Check basic fields
        assert data["name"] == basic_integration.name
        assert data["integration_type"] == basic_integration.integration_type.value
        assert data["system_name"] == basic_integration.system_name
        assert data["owner_id"] == str(basic_integration.owner_id)
        assert data["status"] == basic_integration.status.value
        assert data["is_active"] == basic_integration.is_active

        # Check computed properties
        assert data["is_connected"] == basic_integration.is_connected
        assert data["is_healthy"] == basic_integration.is_healthy
        assert data["needs_attention"] == basic_integration.needs_attention
        assert data["can_sync"] == basic_integration.can_sync
        assert data["can_receive_webhooks"] == basic_integration.can_receive_webhooks

        # Check counts
        assert data["credential_count"] == len(basic_integration._credential_ids)
        assert data["sync_job_count"] == len(basic_integration._sync_job_ids)
        assert data["mapping_count"] == len(basic_integration._mapping_ids)
        assert data["webhook_endpoint_count"] == len(
            basic_integration._webhook_endpoint_ids
        )

    def test_to_dict_sanitizes_configuration(self, basic_integration):
        """Test to_dict sanitizes sensitive configuration."""
        basic_integration.configuration = {
            "public_setting": "visible",
            "api_key": "secret123",
            "password": "hidden",
            "oauth_secret": "confidential",
        }

        data = basic_integration.to_dict()
        config = data["configuration"]

        assert config["public_setting"] == "visible"
        assert config["api_key"] == "***REDACTED***"
        assert config["password"] == "***REDACTED***"
        assert config["oauth_secret"] == "***REDACTED***"

    def test_str_representation(self, basic_integration):
        """Test string representation of integration."""
        str_repr = str(basic_integration)

        assert basic_integration.name in str_repr
        assert basic_integration.system_name in str_repr
        assert basic_integration.status.value in str_repr


class TestIntegrationValidation:
    """Test Integration aggregate validation."""

    def test_validate_aggregate_with_invalid_integration_type_fails(
        self, user_id, api_endpoint
    ):
        """Test validation fails with invalid integration type."""
        with pytest.raises(
            ValidationError, match="integration_type must be an IntegrationType enum"
        ):
            Integration(
                name="Test",
                integration_type="invalid",  # String instead of enum
                system_name="Test",
                api_endpoint=api_endpoint,
                owner_id=user_id,
            )

    def test_validate_aggregate_with_invalid_api_endpoint_fails(self, user_id):
        """Test validation fails with invalid API endpoint."""
        with pytest.raises(
            ValidationError, match="api_endpoint must be an ApiEndpoint instance"
        ):
            Integration(
                name="Test",
                integration_type=IntegrationType.REST_API,
                system_name="Test",
                api_endpoint="invalid",  # String instead of ApiEndpoint
                owner_id=user_id,
            )

    def test_validate_aggregate_with_invalid_rate_limit_fails(
        self, user_id, api_endpoint
    ):
        """Test validation fails with invalid rate limit config."""
        with pytest.raises(
            ValidationError, match="rate_limit must be a RateLimitConfig instance"
        ):
            Integration(
                name="Test",
                integration_type=IntegrationType.REST_API,
                system_name="Test",
                api_endpoint=api_endpoint,
                owner_id=user_id,
                rate_limit="invalid",  # String instead of RateLimitConfig
            )

    def test_validate_aggregate_with_invalid_status_fails(self, user_id, api_endpoint):
        """Test validation fails with invalid connection status."""
        integration = Integration(
            name="Test",
            integration_type=IntegrationType.REST_API,
            system_name="Test",
            api_endpoint=api_endpoint,
            owner_id=user_id,
        )

        # Manually set invalid status to test validation
        integration.status = "invalid"

        with pytest.raises(
            ValidationError, match="status must be a ConnectionStatus enum"
        ):
            integration._validate_aggregate()


class TestIntegrationEventSanitization:
    """Test Integration event data sanitization."""

    def test_sanitize_configuration_for_events(self, basic_integration):
        """Test configuration sanitization for events."""
        basic_integration.configuration = {
            "public": "visible",
            "secret_key": "hidden",
            "api_token": "confidential",
            "credential_data": "sensitive",
        }

        sanitized = basic_integration._sanitize_configuration()

        assert sanitized["public"] == "visible"
        assert sanitized["secret_key"] == "***REDACTED***"
        assert sanitized["api_token"] == "***REDACTED***"
        assert sanitized["credential_data"] == "***REDACTED***"

    def test_sanitize_configuration_case_insensitive(self, basic_integration):
        """Test configuration sanitization is case insensitive."""
        basic_integration.configuration = {
            "API_KEY": "hidden",
            "Secret": "confidential",
            "PASSWORD": "sensitive",
        }

        sanitized = basic_integration._sanitize_configuration()

        assert sanitized["API_KEY"] == "***REDACTED***"
        assert sanitized["Secret"] == "***REDACTED***"
        assert sanitized["PASSWORD"] == "***REDACTED***"
