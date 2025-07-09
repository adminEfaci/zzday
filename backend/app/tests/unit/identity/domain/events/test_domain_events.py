"""
Comprehensive unit tests for Domain Events.

Tests cover:
- Event creation and validation
- Event payload and metadata
- Event serialization
- Event ordering and causality
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.modules.identity.domain.errors import DomainError
from app.modules.identity.domain.events.base import DomainEvent
from app.modules.identity.domain.events.user_events import (
    UserActivatedEvent,
    UserCreatedEvent,
    UserDeactivatedEvent,
    UserDeletedEvent,
    UserEmailChangedEvent,
    UserLockedEvent,
    UserLoggedInEvent,
    UserLoggedOutEvent,
    UserMFADisabledEvent,
    UserMFAEnabledEvent,
    UserPasswordChangedEvent,
    UserProfileUpdatedEvent,
    UserUnlockedEvent,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.ip_address import IpAddress
from app.modules.identity.domain.value_objects.user_id import UserId
from app.modules.identity.domain.value_objects.username import Username


class TestDomainEventBase:
    """Test suite for base DomainEvent functionality."""

    def test_domain_event_creation(self):
        """Test creating a domain event."""
        aggregate_id = UserId.generate()
        
        event = DomainEvent(
            aggregate_id=aggregate_id,
            event_type="TestEvent",
            payload={"key": "value"},
        )
        
        assert event.id is not None
        assert event.aggregate_id == aggregate_id
        assert event.event_type == "TestEvent"
        assert event.payload == {"key": "value"}
        assert event.occurred_at is not None
        assert event.version == 1
        assert event.metadata == {}

    def test_domain_event_with_metadata(self):
        """Test creating event with metadata."""
        event = DomainEvent(
            aggregate_id=UserId.generate(),
            event_type="TestEvent",
            payload={},
            metadata={
                "user_agent": "Mozilla/5.0",
                "ip_address": "192.168.1.1",
                "correlation_id": str(uuid4()),
            }
        )
        
        assert event.metadata["user_agent"] == "Mozilla/5.0"
        assert event.metadata["ip_address"] == "192.168.1.1"
        assert "correlation_id" in event.metadata

    def test_domain_event_immutability(self):
        """Test that domain events are immutable."""
        event = DomainEvent(
            aggregate_id=UserId.generate(),
            event_type="TestEvent",
            payload={"key": "value"},
        )
        
        # Should not be able to modify event
        with pytest.raises(AttributeError):
            event.payload = {"new": "value"}
        
        with pytest.raises(AttributeError):
            event.occurred_at = datetime.now(UTC)

    def test_domain_event_equality(self):
        """Test domain event equality based on ID."""
        aggregate_id = UserId.generate()
        
        # Create two events with same data
        event1 = DomainEvent(
            aggregate_id=aggregate_id,
            event_type="TestEvent",
            payload={"key": "value"},
        )
        
        event2 = DomainEvent(
            aggregate_id=aggregate_id,
            event_type="TestEvent",
            payload={"key": "value"},
        )
        
        # Different IDs mean different events
        assert event1 != event2
        assert event1.id != event2.id

    def test_domain_event_serialization(self):
        """Test serializing domain event to dict/JSON."""
        event = DomainEvent(
            aggregate_id=UserId.generate(),
            event_type="TestEvent",
            payload={"user_name": "John", "action": "login"},
            metadata={"source": "web"},
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["id"] == str(event.id)
        assert event_dict["aggregate_id"] == str(event.aggregate_id)
        assert event_dict["event_type"] == "TestEvent"
        assert event_dict["payload"] == {"user_name": "John", "action": "login"}
        assert event_dict["metadata"] == {"source": "web"}
        assert "occurred_at" in event_dict
        
        # Should be JSON serializable
        json_str = json.dumps(event_dict)
        assert json_str is not None


class TestUserEvents:
    """Test suite for user-specific domain events."""

    def test_user_created_event(self):
        """Test UserCreatedEvent."""
        user_id = UserId.generate()
        email = Email("user@example.com")
        username = Username("johndoe")
        
        event = UserCreatedEvent(
            user_id=user_id,
            email=email,
            username=username,
            user_type="REGULAR",
            registered_from="web",
            ip_address=IpAddress("192.168.1.1"),
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserCreatedEvent"
        assert event.payload["email"] == email.value
        assert event.payload["username"] == username.value
        assert event.payload["user_type"] == "REGULAR"
        assert event.payload["registered_from"] == "web"
        assert event.metadata["ip_address"] == "192.168.1.1"

    def test_user_activated_event(self):
        """Test UserActivatedEvent."""
        user_id = UserId.generate()
        
        event = UserActivatedEvent(
            user_id=user_id,
            activation_method="email_verification",
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserActivatedEvent"
        assert event.payload["activation_method"] == "email_verification"
        assert event.payload["activated_at"] is not None

    def test_user_deactivated_event(self):
        """Test UserDeactivatedEvent."""
        user_id = UserId.generate()
        
        event = UserDeactivatedEvent(
            user_id=user_id,
            reason="User requested deactivation",
            deactivated_by="self",
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserDeactivatedEvent"
        assert event.payload["reason"] == "User requested deactivation"
        assert event.payload["deactivated_by"] == "self"

    def test_user_deleted_event(self):
        """Test UserDeletedEvent."""
        user_id = UserId.generate()
        
        event = UserDeletedEvent(
            user_id=user_id,
            deletion_type="soft",
            reason="GDPR request",
            deleted_by="admin",
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserDeletedEvent"
        assert event.payload["deletion_type"] == "soft"
        assert event.payload["reason"] == "GDPR request"
        assert event.payload["deleted_by"] == "admin"

    def test_user_logged_in_event(self):
        """Test UserLoggedInEvent."""
        user_id = UserId.generate()
        session_id = str(uuid4())
        
        event = UserLoggedInEvent(
            user_id=user_id,
            session_id=session_id,
            ip_address=IpAddress("10.0.0.1"),
            user_agent="Chrome/96.0",
            authentication_method="password",
            mfa_used=True,
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserLoggedInEvent"
        assert event.payload["session_id"] == session_id
        assert event.payload["authentication_method"] == "password"
        assert event.payload["mfa_used"] is True
        assert event.metadata["ip_address"] == "10.0.0.1"
        assert event.metadata["user_agent"] == "Chrome/96.0"

    def test_user_logged_out_event(self):
        """Test UserLoggedOutEvent."""
        user_id = UserId.generate()
        session_id = str(uuid4())
        
        event = UserLoggedOutEvent(
            user_id=user_id,
            session_id=session_id,
            logout_type="manual",
            reason="User initiated",
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserLoggedOutEvent"
        assert event.payload["session_id"] == session_id
        assert event.payload["logout_type"] == "manual"
        assert event.payload["reason"] == "User initiated"

    def test_user_password_changed_event(self):
        """Test UserPasswordChangedEvent."""
        user_id = UserId.generate()
        
        event = UserPasswordChangedEvent(
            user_id=user_id,
            change_reason="regular_update",
            forced=False,
            ip_address=IpAddress("192.168.1.1"),
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserPasswordChangedEvent"
        assert event.payload["change_reason"] == "regular_update"
        assert event.payload["forced"] is False
        assert event.metadata["ip_address"] == "192.168.1.1"

    def test_user_email_changed_event(self):
        """Test UserEmailChangedEvent."""
        user_id = UserId.generate()
        old_email = Email("old@example.com")
        new_email = Email("new@example.com")
        
        event = UserEmailChangedEvent(
            user_id=user_id,
            old_email=old_email,
            new_email=new_email,
            change_reason="user_requested",
            verification_required=True,
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserEmailChangedEvent"
        assert event.payload["old_email"] == old_email.value
        assert event.payload["new_email"] == new_email.value
        assert event.payload["change_reason"] == "user_requested"
        assert event.payload["verification_required"] is True

    def test_user_profile_updated_event(self):
        """Test UserProfileUpdatedEvent."""
        user_id = UserId.generate()
        
        event = UserProfileUpdatedEvent(
            user_id=user_id,
            changed_fields=["first_name", "last_name", "phone"],
            old_values={
                "first_name": "John",
                "last_name": "Doe",
                "phone": "+1234567890",
            },
            new_values={
                "first_name": "Jane",
                "last_name": "Smith",
                "phone": "+0987654321",
            },
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserProfileUpdatedEvent"
        assert event.payload["changed_fields"] == ["first_name", "last_name", "phone"]
        assert event.payload["old_values"]["first_name"] == "John"
        assert event.payload["new_values"]["first_name"] == "Jane"

    def test_user_locked_event(self):
        """Test UserLockedEvent."""
        user_id = UserId.generate()
        locked_until = datetime.now(UTC) + timedelta(hours=1)
        
        event = UserLockedEvent(
            user_id=user_id,
            reason="Too many failed login attempts",
            locked_until=locked_until,
            locked_by="system",
            failed_attempts=5,
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserLockedEvent"
        assert event.payload["reason"] == "Too many failed login attempts"
        assert event.payload["locked_until"] == locked_until.isoformat()
        assert event.payload["locked_by"] == "system"
        assert event.payload["failed_attempts"] == 5

    def test_user_unlocked_event(self):
        """Test UserUnlockedEvent."""
        user_id = UserId.generate()
        
        event = UserUnlockedEvent(
            user_id=user_id,
            reason="Manual unlock by admin",
            unlocked_by="admin@example.com",
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserUnlockedEvent"
        assert event.payload["reason"] == "Manual unlock by admin"
        assert event.payload["unlocked_by"] == "admin@example.com"

    def test_user_mfa_enabled_event(self):
        """Test UserMFAEnabledEvent."""
        user_id = UserId.generate()
        
        event = UserMFAEnabledEvent(
            user_id=user_id,
            mfa_type="totp",
            device_name="iPhone 12",
            backup_codes_generated=8,
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserMFAEnabledEvent"
        assert event.payload["mfa_type"] == "totp"
        assert event.payload["device_name"] == "iPhone 12"
        assert event.payload["backup_codes_generated"] == 8

    def test_user_mfa_disabled_event(self):
        """Test UserMFADisabledEvent."""
        user_id = UserId.generate()
        
        event = UserMFADisabledEvent(
            user_id=user_id,
            reason="User requested",
            disabled_by="self",
            mfa_types_removed=["totp", "sms"],
        )
        
        assert event.aggregate_id == user_id
        assert event.event_type == "UserMFADisabledEvent"
        assert event.payload["reason"] == "User requested"
        assert event.payload["disabled_by"] == "self"
        assert event.payload["mfa_types_removed"] == ["totp", "sms"]


class TestEventOrdering:
    """Test suite for event ordering and causality."""

    def test_event_timestamps_are_ordered(self):
        """Test that events have properly ordered timestamps."""
        user_id = UserId.generate()
        
        events = []
        for i in range(10):
            event = UserProfileUpdatedEvent(
                user_id=user_id,
                changed_fields=["field"],
                old_values={"field": f"old{i}"},
                new_values={"field": f"new{i}"},
            )
            events.append(event)
            # Small delay to ensure different timestamps
            import time
            time.sleep(0.001)
        
        # Events should be in chronological order
        for i in range(len(events) - 1):
            assert events[i].occurred_at <= events[i + 1].occurred_at

    def test_event_causality_chain(self):
        """Test event causality chain with correlation IDs."""
        user_id = UserId.generate()
        correlation_id = str(uuid4())
        
        # Create chain of events with same correlation ID
        created_event = UserCreatedEvent(
            user_id=user_id,
            email=Email("user@example.com"),
            username=Username("user"),
            metadata={"correlation_id": correlation_id},
        )
        
        activated_event = UserActivatedEvent(
            user_id=user_id,
            activation_method="auto",
            metadata={
                "correlation_id": correlation_id,
                "caused_by_event_id": str(created_event.id),
            },
        )
        
        login_event = UserLoggedInEvent(
            user_id=user_id,
            session_id=str(uuid4()),
            authentication_method="password",
            metadata={
                "correlation_id": correlation_id,
                "caused_by_event_id": str(activated_event.id),
            },
        )
        
        # All events share correlation ID
        assert created_event.metadata.get("correlation_id") == correlation_id
        assert activated_event.metadata.get("correlation_id") == correlation_id
        assert login_event.metadata.get("correlation_id") == correlation_id
        
        # Events reference their causes
        assert activated_event.metadata["caused_by_event_id"] == str(created_event.id)
        assert login_event.metadata["caused_by_event_id"] == str(activated_event.id)


class TestEventValidation:
    """Test suite for event validation."""

    def test_event_payload_validation(self):
        """Test that event payloads are validated."""
        user_id = UserId.generate()
        
        # Should validate email format
        with pytest.raises(DomainError):
            UserCreatedEvent(
                user_id=user_id,
                email=Email("invalid-email"),  # This would fail in Email value object
                username=Username("user"),
            )

    def test_event_aggregate_id_required(self):
        """Test that aggregate ID is required."""
        with pytest.raises(TypeError):
            DomainEvent(
                aggregate_id=None,
                event_type="TestEvent",
                payload={},
            )

    def test_event_type_required(self):
        """Test that event type is required."""
        with pytest.raises(ValueError):
            DomainEvent(
                aggregate_id=UserId.generate(),
                event_type="",
                payload={},
            )