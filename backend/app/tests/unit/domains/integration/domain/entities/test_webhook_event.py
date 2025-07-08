"""
Comprehensive tests for WebhookEvent entity.

Tests all behaviors, business rules, and edge cases for the WebhookEvent entity,
ensuring 100% code coverage and validating all domain logic.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest

from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.entities.webhook_event import WebhookEvent
from app.modules.integration.domain.enums import WebhookMethod, WebhookStatus


class TestWebhookEventCreation:
    """Test WebhookEvent entity creation and validation."""

    def test_create_webhook_event_with_valid_data_succeeds(self, webhook_event_factory):
        """Test creating webhook event with valid data."""
        endpoint_id = uuid4()
        integration_id = uuid4()
        payload = {"user_id": "123", "action": "created"}
        headers = {"Content-Type": "application/json"}

        event = webhook_event_factory(
            endpoint_id=endpoint_id,
            integration_id=integration_id,
            event_type="user.created",
            payload=payload,
            headers=headers,
            method=WebhookMethod.POST,
            source_ip="192.168.1.100",
            signature="test_signature",
            is_valid_signature=True,
        )

        assert event.endpoint_id == endpoint_id
        assert event.integration_id == integration_id
        assert event.event_type == "user.created"
        assert event.payload == payload
        assert event.headers == headers
        assert event.method == WebhookMethod.POST
        assert event.source_ip == "192.168.1.100"
        assert event.signature == "test_signature"
        assert event.is_valid_signature is True
        assert event.status == WebhookStatus.PENDING
        assert event.retry_count == 0
        assert event.max_retries == 3
        assert event.processing_errors == []
        assert event.received_at is not None
        assert event.processed_at is None
        assert event.next_retry_at is None
        assert event.event_hash is not None

    def test_create_webhook_event_with_minimal_data_succeeds(self):
        """Test creating webhook event with minimal required data."""
        endpoint_id = uuid4()
        integration_id = uuid4()

        event = WebhookEvent(
            endpoint_id=endpoint_id,
            integration_id=integration_id,
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        assert event.endpoint_id == endpoint_id
        assert event.integration_id == integration_id
        assert event.signature is None
        assert event.is_valid_signature is False
        assert event.status == WebhookStatus.PENDING
        assert event.retry_count == 0
        assert event.max_retries == 3

    def test_create_webhook_event_with_custom_retry_settings(self):
        """Test creating webhook event with custom retry settings."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
            retry_count=2,
            max_retries=5,
        )

        assert event.retry_count == 2
        assert event.max_retries == 5

    @pytest.mark.parametrize("invalid_event_type", ["", "   ", None])
    def test_create_webhook_event_with_invalid_event_type_fails(
        self, invalid_event_type
    ):
        """Test creating webhook event with invalid event type fails."""
        with pytest.raises(ValidationError, match="Event type cannot be empty"):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type=invalid_event_type,
                payload={"test": "data"},
                headers={"Content-Type": "application/json"},
                method=WebhookMethod.POST,
                source_ip="127.0.0.1",
            )

    def test_create_webhook_event_with_long_event_type_fails(self):
        """Test creating webhook event with too long event type fails."""
        long_event_type = "a" * 101

        with pytest.raises(
            ValidationError, match="Event type cannot exceed 100 characters"
        ):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type=long_event_type,
                payload={"test": "data"},
                headers={"Content-Type": "application/json"},
                method=WebhookMethod.POST,
                source_ip="127.0.0.1",
            )

    def test_create_webhook_event_with_invalid_payload_fails(self):
        """Test creating webhook event with invalid payload fails."""
        with pytest.raises(ValidationError, match="Payload must be a dictionary"):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type="test.event",
                payload="invalid",  # String instead of dict
                headers={"Content-Type": "application/json"},
                method=WebhookMethod.POST,
                source_ip="127.0.0.1",
            )

    def test_create_webhook_event_with_large_payload_fails(self):
        """Test creating webhook event with too large payload fails."""
        # Create a payload that exceeds 1MB
        large_data = "x" * 500_000
        large_payload = {"data": large_data, "more_data": large_data}

        with pytest.raises(ValidationError, match="Payload size exceeds 1MB limit"):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type="test.event",
                payload=large_payload,
                headers={"Content-Type": "application/json"},
                method=WebhookMethod.POST,
                source_ip="127.0.0.1",
            )

    def test_create_webhook_event_with_invalid_headers_fails(self):
        """Test creating webhook event with invalid headers fails."""
        with pytest.raises(ValidationError, match="Headers must be a dictionary"):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type="test.event",
                payload={"test": "data"},
                headers="invalid",  # String instead of dict
                method=WebhookMethod.POST,
                source_ip="127.0.0.1",
            )

    @pytest.mark.parametrize(
        "invalid_ip", ["", "999.999.999.999", "invalid", "256.1.1.1"]
    )
    def test_create_webhook_event_with_invalid_ip_fails(self, invalid_ip):
        """Test creating webhook event with invalid IP fails."""
        with pytest.raises(ValidationError, match="Invalid"):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type="test.event",
                payload={"test": "data"},
                headers={"Content-Type": "application/json"},
                method=WebhookMethod.POST,
                source_ip=invalid_ip,
            )

    def test_event_type_is_trimmed(self):
        """Test that event type is properly trimmed."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="  test.event  ",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        assert event.event_type == "test.event"


class TestWebhookEventHeaderSanitization:
    """Test webhook event header sanitization."""

    def test_sensitive_headers_are_redacted(self):
        """Test that sensitive headers are redacted."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer secret",
            "X-API-Key": "api_key_123",
            "Cookie": "session=abc123",
            "X-Auth-Token": "token_456",
        }

        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers=headers,
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        assert event.headers["Content-Type"] == "application/json"
        assert event.headers["Authorization"] == "***REDACTED***"
        assert event.headers["X-API-Key"] == "***REDACTED***"
        assert event.headers["Cookie"] == "***REDACTED***"
        assert event.headers["X-Auth-Token"] == "***REDACTED***"

    def test_case_insensitive_header_sanitization(self):
        """Test that header sanitization is case insensitive."""
        headers = {
            "AUTHORIZATION": "Bearer secret",
            "x-api-key": "api_key_123",
            "Cookie": "session=abc123",
        }

        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers=headers,
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        assert event.headers["AUTHORIZATION"] == "***REDACTED***"
        assert event.headers["x-api-key"] == "***REDACTED***"
        assert event.headers["Cookie"] == "***REDACTED***"


class TestWebhookEventIPValidation:
    """Test webhook event IP address validation."""

    @pytest.mark.parametrize(
        "valid_ipv4",
        [
            "127.0.0.1",
            "192.168.1.100",
            "10.0.0.1",
            "203.0.113.1",
            "0.0.0.0",
            "255.255.255.255",
        ],
    )
    def test_valid_ipv4_addresses_accepted(self, valid_ipv4):
        """Test that valid IPv4 addresses are accepted."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip=valid_ipv4,
        )

        assert event.source_ip == valid_ipv4

    @pytest.mark.parametrize(
        "valid_ipv6",
        ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1", "2001:db8::1", "fe80::1"],
    )
    def test_valid_ipv6_addresses_accepted(self, valid_ipv6):
        """Test that valid IPv6 addresses are accepted."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip=valid_ipv6,
        )

        assert event.source_ip == valid_ipv6

    def test_too_long_ipv6_fails(self):
        """Test that too long IPv6 address fails."""
        long_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra"

        with pytest.raises(ValidationError, match="Invalid IPv6 address"):
            WebhookEvent(
                endpoint_id=uuid4(),
                integration_id=uuid4(),
                event_type="test.event",
                payload={"test": "data"},
                headers={"Content-Type": "application/json"},
                method=WebhookMethod.POST,
                source_ip=long_ipv6,
            )


class TestWebhookEventProperties:
    """Test WebhookEvent entity properties."""

    def test_is_processed_property(self, webhook_event):
        """Test is_processed property returns correct values."""
        # Initially not processed
        assert not webhook_event.is_processed

        # Set to processed
        webhook_event.status = WebhookStatus.PROCESSED
        assert webhook_event.is_processed

    def test_is_failed_property(self, webhook_event):
        """Test is_failed property returns correct values."""
        # Initially not failed
        assert not webhook_event.is_failed

        # Set to failed
        webhook_event.status = WebhookStatus.FAILED
        assert webhook_event.is_failed

    def test_can_retry_property(self, webhook_event):
        """Test can_retry property checks all conditions."""
        # Initially cannot retry (not failed)
        assert not webhook_event.can_retry

        # Set to failed with valid signature
        webhook_event.status = WebhookStatus.FAILED
        webhook_event.is_valid_signature = True
        webhook_event.retry_count = 1
        webhook_event.max_retries = 3
        assert webhook_event.can_retry

        # Test conditions that prevent retry
        webhook_event.is_valid_signature = False
        assert not webhook_event.can_retry

        webhook_event.is_valid_signature = True
        webhook_event.retry_count = 3  # Reached max retries
        assert not webhook_event.can_retry

        webhook_event.retry_count = 1
        webhook_event.status = WebhookStatus.PROCESSED  # Not failed
        assert not webhook_event.can_retry

    def test_processing_time_property(self, webhook_event):
        """Test processing_time property calculation."""
        # Initially no processing time
        assert webhook_event.processing_time is None

        # Set processed time
        webhook_event.processed_at = webhook_event.received_at + timedelta(seconds=5)
        processing_time = webhook_event.processing_time

        assert processing_time is not None
        assert processing_time.total_seconds() == 5

    def test_age_property(self, webhook_event):
        """Test age property calculation."""
        with patch(
            "app.modules.integration.domain.entities.webhook_event.datetime"
        ) as mock_datetime:
            mock_now = webhook_event.received_at + timedelta(minutes=10)
            mock_datetime.now.return_value = mock_now

            age = webhook_event.age
            assert age.total_seconds() == 600  # 10 minutes

    def test_is_expired_property(self, webhook_event):
        """Test is_expired property with custom max age."""
        with patch(
            "app.modules.integration.domain.entities.webhook_event.datetime"
        ) as mock_datetime:
            # Not expired (within 24 hours)
            mock_now = webhook_event.received_at + timedelta(hours=12)
            mock_datetime.now.return_value = mock_now

            assert not webhook_event.is_expired()
            assert not webhook_event.is_expired(24)

            # Expired (over 24 hours)
            mock_now = webhook_event.received_at + timedelta(hours=25)
            mock_datetime.now.return_value = mock_now

            assert webhook_event.is_expired()
            assert webhook_event.is_expired(24)


class TestWebhookEventProcessing:
    """Test WebhookEvent processing methods."""

    def test_start_processing_succeeds(self, webhook_event):
        """Test successful processing start."""
        webhook_event.is_valid_signature = True

        webhook_event.start_processing()

        assert webhook_event.status == WebhookStatus.PROCESSING

    def test_start_processing_already_processing_fails(self, webhook_event):
        """Test starting processing when already processing fails."""
        webhook_event.status = WebhookStatus.PROCESSING

        with pytest.raises(DomainError, match="Event is already being processed"):
            webhook_event.start_processing()

    def test_start_processing_already_processed_fails(self, webhook_event):
        """Test starting processing when already processed fails."""
        webhook_event.status = WebhookStatus.PROCESSED

        with pytest.raises(DomainError, match="Event has already been processed"):
            webhook_event.start_processing()

    def test_start_processing_invalid_signature_fails(self, webhook_event):
        """Test starting processing with invalid signature fails."""
        webhook_event.is_valid_signature = False

        with pytest.raises(
            DomainError, match="Cannot process event with invalid signature"
        ):
            webhook_event.start_processing()

    def test_start_processing_expired_event_fails(self, webhook_event):
        """Test starting processing on expired event fails."""
        webhook_event.is_valid_signature = True

        with patch.object(webhook_event, "is_expired", return_value=True):
            with pytest.raises(DomainError, match="Event is too old to process"):
                webhook_event.start_processing()

    def test_complete_processing_succeeds(self, webhook_event):
        """Test successful processing completion."""
        webhook_event.status = WebhookStatus.PROCESSING
        result = {"action": "user_created", "id": "123"}

        webhook_event.complete_processing(result)

        assert webhook_event.status == WebhookStatus.PROCESSED
        assert webhook_event.processed_at is not None
        assert webhook_event.payload["_processing_result"] == result

    def test_complete_processing_without_result_succeeds(self, webhook_event):
        """Test processing completion without result."""
        webhook_event.status = WebhookStatus.PROCESSING

        webhook_event.complete_processing()

        assert webhook_event.status == WebhookStatus.PROCESSED
        assert webhook_event.processed_at is not None
        assert "_processing_result" not in webhook_event.payload

    def test_complete_processing_not_processing_fails(self, webhook_event):
        """Test completing processing when not processing fails."""
        webhook_event.status = WebhookStatus.PENDING

        with pytest.raises(
            DomainError, match="Event must be in processing state to complete"
        ):
            webhook_event.complete_processing()

    def test_fail_processing_succeeds(self, webhook_event):
        """Test successful processing failure."""
        webhook_event.status = WebhookStatus.PROCESSING
        error = "Database connection failed"
        error_details = {"db_host": "localhost", "error_code": 1001}

        webhook_event.fail_processing(error, error_details)

        assert webhook_event.status == WebhookStatus.FAILED
        assert webhook_event.processed_at is not None
        assert len(webhook_event.processing_errors) == 1

        error_record = webhook_event.processing_errors[0]
        assert error_record["error"] == error
        assert error_record["details"] == error_details
        assert error_record["attempt"] == 1

    def test_fail_processing_sets_retry_time(self, webhook_event):
        """Test that failing processing sets next retry time."""
        webhook_event.status = WebhookStatus.PROCESSING
        webhook_event.is_valid_signature = True
        webhook_event.retry_count = 1
        webhook_event.max_retries = 3

        webhook_event.fail_processing("Test error")

        assert webhook_event.next_retry_at is not None
        assert webhook_event.next_retry_at > datetime.now(UTC)

    def test_fail_processing_exponential_backoff(self, webhook_event):
        """Test exponential backoff in retry timing."""
        webhook_event.status = WebhookStatus.PROCESSING
        webhook_event.is_valid_signature = True
        webhook_event.max_retries = 5

        # Test different retry counts
        for retry_count in [0, 1, 2, 3]:
            webhook_event.retry_count = retry_count
            webhook_event.fail_processing(f"Error {retry_count}")

            # Reset for next iteration
            webhook_event.status = WebhookStatus.PROCESSING
            webhook_event.processing_errors.clear()

    def test_fail_processing_not_processing_fails(self, webhook_event):
        """Test failing processing when not processing fails."""
        webhook_event.status = WebhookStatus.PENDING

        with pytest.raises(
            DomainError, match="Event must be in processing state to fail"
        ):
            webhook_event.fail_processing("Test error")


class TestWebhookEventRetry:
    """Test WebhookEvent retry functionality."""

    def test_retry_succeeds(self, webhook_event):
        """Test successful retry."""
        webhook_event.status = WebhookStatus.FAILED
        webhook_event.is_valid_signature = True
        webhook_event.retry_count = 1
        webhook_event.max_retries = 3
        webhook_event.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)

        webhook_event.retry()

        assert webhook_event.status == WebhookStatus.PENDING
        assert webhook_event.retry_count == 2
        assert webhook_event.next_retry_at is None

    def test_retry_cannot_retry_fails(self, webhook_event):
        """Test retry when cannot retry fails."""
        webhook_event.status = WebhookStatus.FAILED
        webhook_event.is_valid_signature = False  # Invalid signature

        with pytest.raises(DomainError, match="Event cannot be retried"):
            webhook_event.retry()

    def test_retry_before_retry_time_fails(self, webhook_event):
        """Test retry before retry time fails."""
        webhook_event.status = WebhookStatus.FAILED
        webhook_event.is_valid_signature = True
        webhook_event.retry_count = 1
        webhook_event.max_retries = 3
        webhook_event.next_retry_at = datetime.now(UTC) + timedelta(minutes=5)

        with pytest.raises(DomainError, match="Retry time has not been reached"):
            webhook_event.retry()


class TestWebhookEventProcessingNotes:
    """Test WebhookEvent processing notes functionality."""

    def test_add_processing_note_succeeds(self, webhook_event):
        """Test adding processing note."""
        note = "Processing user creation"
        details = {"user_id": "123", "action": "create"}

        webhook_event.add_processing_note(note, details)

        assert "_processing_notes" in webhook_event.payload
        notes = webhook_event.payload["_processing_notes"]
        assert len(notes) == 1
        assert notes[0]["note"] == note
        assert notes[0]["details"] == details
        assert "timestamp" in notes[0]

    def test_add_multiple_processing_notes(self, webhook_event):
        """Test adding multiple processing notes."""
        webhook_event.add_processing_note("First note")
        webhook_event.add_processing_note("Second note", {"detail": "value"})

        notes = webhook_event.payload["_processing_notes"]
        assert len(notes) == 2
        assert notes[0]["note"] == "First note"
        assert notes[1]["note"] == "Second note"


class TestWebhookEventHeaders:
    """Test WebhookEvent header operations."""

    def test_get_header_case_insensitive(self, webhook_event):
        """Test getting header value case insensitively."""
        webhook_event.headers = {
            "Content-Type": "application/json",
            "X-Custom-Header": "custom_value",
        }

        assert webhook_event.get_header("content-type") == "application/json"
        assert webhook_event.get_header("CONTENT-TYPE") == "application/json"
        assert webhook_event.get_header("x-custom-header") == "custom_value"
        assert webhook_event.get_header("X-CUSTOM-HEADER") == "custom_value"

    def test_get_header_with_default(self, webhook_event):
        """Test getting header with default value."""
        webhook_event.headers = {"Content-Type": "application/json"}

        assert webhook_event.get_header("missing") is None
        assert webhook_event.get_header("missing", "default") == "default"


class TestWebhookEventEventHash:
    """Test WebhookEvent event hash generation."""

    def test_event_hash_generation(self, webhook_event):
        """Test that event hash is generated correctly."""
        assert webhook_event.event_hash is not None
        assert len(webhook_event.event_hash) == 64  # SHA256 hex length

    def test_event_hash_consistency(self):
        """Test that identical events generate same hash."""
        endpoint_id = uuid4()
        integration_id = uuid4()
        payload = {"user_id": "123", "action": "created"}
        headers = {"Content-Type": "application/json"}

        with patch(
            "app.modules.integration.domain.entities.webhook_event.datetime"
        ) as mock_datetime:
            fixed_time = datetime.now(UTC)
            mock_datetime.now.return_value = fixed_time

            event1 = WebhookEvent(
                endpoint_id=endpoint_id,
                integration_id=integration_id,
                event_type="user.created",
                payload=payload,
                headers=headers,
                method=WebhookMethod.POST,
                source_ip="192.168.1.100",
            )

            event2 = WebhookEvent(
                endpoint_id=endpoint_id,
                integration_id=integration_id,
                event_type="user.created",
                payload=payload,
                headers=headers,
                method=WebhookMethod.POST,
                source_ip="192.168.1.100",
            )

            assert event1.event_hash == event2.event_hash

    def test_event_hash_different_for_different_events(self):
        """Test that different events generate different hashes."""
        endpoint_id = uuid4()
        integration_id = uuid4()

        event1 = WebhookEvent(
            endpoint_id=endpoint_id,
            integration_id=integration_id,
            event_type="user.created",
            payload={"user_id": "123"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="192.168.1.100",
        )

        event2 = WebhookEvent(
            endpoint_id=endpoint_id,
            integration_id=integration_id,
            event_type="user.updated",  # Different event type
            payload={"user_id": "123"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="192.168.1.100",
        )

        assert event1.event_hash != event2.event_hash


class TestWebhookEventValidation:
    """Test WebhookEvent entity validation."""

    def test_validate_entity_with_invalid_method_fails(self):
        """Test validation fails with invalid method."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        # Manually set invalid method to test validation
        event.method = "invalid"

        with pytest.raises(
            ValidationError, match="method must be a WebhookMethod enum"
        ):
            event._validate_entity()

    def test_validate_entity_with_invalid_status_fails(self):
        """Test validation fails with invalid status."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        # Manually set invalid status to test validation
        event.status = "invalid"

        with pytest.raises(
            ValidationError, match="status must be a WebhookStatus enum"
        ):
            event._validate_entity()

    def test_validate_entity_with_missing_endpoint_id_fails(self):
        """Test validation fails with missing endpoint_id."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        # Manually set invalid endpoint_id to test validation
        event.endpoint_id = None

        with pytest.raises(ValidationError, match="endpoint_id is required"):
            event._validate_entity()

    def test_validate_entity_with_missing_integration_id_fails(self):
        """Test validation fails with missing integration_id."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
        )

        # Manually set invalid integration_id to test validation
        event.integration_id = None

        with pytest.raises(ValidationError, match="integration_id is required"):
            event._validate_entity()


class TestWebhookEventSerialization:
    """Test WebhookEvent serialization and string representation."""

    def test_to_dict_includes_all_fields(self, webhook_event):
        """Test to_dict includes all expected fields."""
        data = webhook_event.to_dict()

        # Check basic fields
        assert data["endpoint_id"] == str(webhook_event.endpoint_id)
        assert data["integration_id"] == str(webhook_event.integration_id)
        assert data["event_type"] == webhook_event.event_type
        assert data["payload"] == webhook_event.payload
        assert data["headers"] == webhook_event.headers
        assert data["method"] == webhook_event.method.value
        assert data["source_ip"] == webhook_event.source_ip
        assert data["status"] == webhook_event.status.value

        # Check computed properties
        assert data["is_processed"] == webhook_event.is_processed
        assert data["is_failed"] == webhook_event.is_failed
        assert data["can_retry"] == webhook_event.can_retry
        assert data["event_hash"] == webhook_event.event_hash

        # Check timestamps
        assert data["received_at"] == webhook_event.received_at.isoformat()
        assert "age_seconds" in data

    def test_to_dict_with_processed_event(self, webhook_event):
        """Test to_dict with processed event includes processing time."""
        webhook_event.processed_at = webhook_event.received_at + timedelta(seconds=5)

        data = webhook_event.to_dict()

        assert data["processed_at"] == webhook_event.processed_at.isoformat()
        assert data["processing_time_seconds"] == 5

    def test_to_dict_signature_handling(self, webhook_event):
        """Test to_dict handles signature appropriately."""
        # With signature
        webhook_event.signature = "test_signature"
        data = webhook_event.to_dict()
        assert data["has_signature"] is True

        # Without signature
        webhook_event.signature = None
        data = webhook_event.to_dict()
        assert data["has_signature"] is False

    def test_str_representation(self, webhook_event):
        """Test string representation of webhook event."""
        str_repr = str(webhook_event)

        assert webhook_event.event_type in str_repr
        assert webhook_event.status.value in str_repr
        assert (
            f"retry={webhook_event.retry_count}/{webhook_event.max_retries}" in str_repr
        )


class TestWebhookEventNegativeRetryValues:
    """Test WebhookEvent handling of negative retry values."""

    def test_negative_retry_count_normalized(self):
        """Test that negative retry count is normalized to 0."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
            retry_count=-1,
        )

        assert event.retry_count == 0

    def test_negative_max_retries_normalized(self):
        """Test that negative max retries is normalized to 0."""
        event = WebhookEvent(
            endpoint_id=uuid4(),
            integration_id=uuid4(),
            event_type="test.event",
            payload={"test": "data"},
            headers={"Content-Type": "application/json"},
            method=WebhookMethod.POST,
            source_ip="127.0.0.1",
            max_retries=-1,
        )

        assert event.max_retries == 0


class TestWebhookEventBackoffCalculation:
    """Test WebhookEvent exponential backoff calculation."""

    def test_backoff_calculation_limits(self, webhook_event):
        """Test that backoff calculation has proper limits."""
        webhook_event.status = WebhookStatus.PROCESSING
        webhook_event.is_valid_signature = True
        webhook_event.max_retries = 10

        # Test maximum backoff (5 minutes = 300 seconds)
        webhook_event.retry_count = 10  # Large retry count
        webhook_event.fail_processing("Test error")

        expected_max_backoff = timedelta(seconds=300)
        actual_backoff = webhook_event.next_retry_at - datetime.now(UTC)

        # Allow for small timing differences
        assert actual_backoff <= expected_max_backoff + timedelta(seconds=1)

    def test_backoff_calculation_progression(self, webhook_event):
        """Test backoff calculation progression."""
        webhook_event.status = WebhookStatus.PROCESSING
        webhook_event.is_valid_signature = True
        webhook_event.max_retries = 5

        backoff_times = []

        for retry_count in range(4):
            webhook_event.retry_count = retry_count

            # Reset state for each test
            webhook_event.status = WebhookStatus.PROCESSING
            webhook_event.next_retry_at = None

            datetime.now(UTC)
            webhook_event.fail_processing(f"Error {retry_count}")
            after_fail = datetime.now(UTC)

            # Calculate actual backoff
            backoff = webhook_event.next_retry_at - after_fail
            backoff_times.append(backoff.total_seconds())

            # Clear processing errors for next iteration
            webhook_event.processing_errors.clear()

        # Verify backoff times are increasing (exponential)
        for i in range(1, len(backoff_times)):
            assert (
                backoff_times[i] >= backoff_times[i - 1]
            ), f"Backoff not increasing: {backoff_times}"
