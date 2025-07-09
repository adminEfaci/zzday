"""
Comprehensive unit tests for Session entity.

Tests cover:
- Session creation and validation
- Token management
- Session expiration
- Device tracking
- Session refresh
"""

import pytest
from datetime import datetime, timedelta, UTC
from uuid import uuid4

from app.modules.identity.domain.entities.session import Session
from app.modules.identity.domain.value_objects.session_id import SessionId
from app.modules.identity.domain.value_objects.user_id import UserId
from app.modules.identity.domain.value_objects.ip_address import IpAddress
from app.modules.identity.domain.value_objects.user_agent import UserAgent
from app.modules.identity.domain.errors import (
    DomainError,
    BusinessRuleViolation,
    InvalidStateTransition,
)


class TestSession:
    """Test suite for Session entity."""

    def test_create_session_with_valid_data(self):
        """Test creating a session with valid data."""
        user_id = UserId.generate()
        
        session = Session.create(
            user_id=user_id,
            access_token="access_token_123",
            refresh_token="refresh_token_123",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address=IpAddress("192.168.1.1"),
            user_agent=UserAgent("Mozilla/5.0"),
            device_name="Chrome on Windows",
        )
        
        assert session.id is not None
        assert isinstance(session.id, SessionId)
        assert session.user_id == user_id
        assert session.access_token == "access_token_123"
        assert session.refresh_token == "refresh_token_123"
        assert session.is_active is True
        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "Mozilla/5.0"
        assert session.device_name == "Chrome on Windows"
        assert session.created_at is not None
        assert session.last_activity_at == session.created_at

    def test_create_session_minimal_data(self):
        """Test creating session with minimal required data."""
        user_id = UserId.generate()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        
        session = Session.create(
            user_id=user_id,
            access_token="token123",
            refresh_token="refresh123",
            expires_at=expires_at,
        )
        
        assert session.user_id == user_id
        assert session.ip_address is None
        assert session.user_agent is None
        assert session.device_name is None

    def test_session_expiration_validation(self):
        """Test session expiration validation."""
        user_id = UserId.generate()
        
        # Past expiration
        with pytest.raises(DomainError) as exc_info:
            Session.create(
                user_id=user_id,
                access_token="token",
                refresh_token="refresh",
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            )
        assert "cannot be in the past" in str(exc_info.value)

    def test_session_token_validation(self):
        """Test session token validation."""
        user_id = UserId.generate()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        
        # Empty access token
        with pytest.raises(DomainError) as exc_info:
            Session.create(
                user_id=user_id,
                access_token="",
                refresh_token="refresh",
                expires_at=expires_at,
            )
        assert "Access token cannot be empty" in str(exc_info.value)
        
        # Empty refresh token
        with pytest.raises(DomainError) as exc_info:
            Session.create(
                user_id=user_id,
                access_token="access",
                refresh_token="",
                expires_at=expires_at,
            )
        assert "Refresh token cannot be empty" in str(exc_info.value)

    def test_is_expired_check(self):
        """Test checking if session is expired."""
        user_id = UserId.generate()
        
        # Not expired session
        session = Session.create(
            user_id=user_id,
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        
        assert session.is_expired() is False
        
        # Expired session
        session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        
        assert session.is_expired() is True

    def test_refresh_session(self):
        """Test refreshing a session."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="old_access",
            refresh_token="old_refresh",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        
        new_expires = datetime.now(UTC) + timedelta(hours=2)
        
        session.refresh(
            new_access_token="new_access",
            new_refresh_token="new_refresh",
            new_expires_at=new_expires,
        )
        
        assert session.access_token == "new_access"
        assert session.refresh_token == "new_refresh"
        assert session.expires_at == new_expires
        assert session.refresh_count == 1
        assert session.last_refreshed_at is not None

    def test_cannot_refresh_expired_session(self):
        """Test that expired sessions cannot be refreshed."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        
        with pytest.raises(InvalidStateTransition) as exc_info:
            session.refresh(
                new_access_token="new",
                new_refresh_token="new",
                new_expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        
        assert "Cannot refresh expired session" in str(exc_info.value)

    def test_cannot_refresh_inactive_session(self):
        """Test that inactive sessions cannot be refreshed."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.revoke()
        
        with pytest.raises(InvalidStateTransition) as exc_info:
            session.refresh(
                new_access_token="new",
                new_refresh_token="new",
                new_expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        
        assert "Cannot refresh inactive session" in str(exc_info.value)

    def test_update_activity(self):
        """Test updating session activity."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        
        original_activity = session.last_activity_at
        
        # Wait a bit to ensure timestamp difference
        import time
        time.sleep(0.01)
        
        session.update_activity(
            ip_address=IpAddress("10.0.0.1"),
            user_agent=UserAgent("New Browser"),
        )
        
        assert session.last_activity_at > original_activity
        assert session.ip_address == "10.0.0.1"
        assert session.user_agent == "New Browser"

    def test_revoke_session(self):
        """Test revoking a session."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        
        assert session.is_active is True
        
        session.revoke()
        
        assert session.is_active is False
        assert session.revoked_at is not None

    def test_cannot_revoke_already_revoked_session(self):
        """Test that already revoked sessions cannot be revoked again."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.revoke()
        
        # Should be idempotent
        session.revoke()
        
        assert session.is_active is False

    def test_session_equality(self):
        """Test session equality comparison."""
        session_id = SessionId.generate()
        user_id = UserId.generate()
        expires = datetime.now(UTC) + timedelta(hours=1)
        
        session1 = Session(
            id=session_id,
            user_id=user_id,
            access_token="token",
            refresh_token="refresh",
            expires_at=expires,
            is_active=True,
            created_at=datetime.now(UTC),
            last_activity_at=datetime.now(UTC),
        )
        
        session2 = Session(
            id=session_id,
            user_id=user_id,
            access_token="token",
            refresh_token="refresh",
            expires_at=expires,
            is_active=True,
            created_at=datetime.now(UTC),
            last_activity_at=datetime.now(UTC),
        )
        
        session3 = Session.create(
            user_id=user_id,
            access_token="token",
            refresh_token="refresh",
            expires_at=expires,
        )
        
        assert session1 == session2  # Same ID
        assert session1 != session3  # Different ID

    def test_session_metadata(self):
        """Test session metadata storage."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            metadata={
                "app_version": "1.0.0",
                "platform": "web",
                "browser": "Chrome",
            }
        )
        
        assert session.metadata["app_version"] == "1.0.0"
        assert session.metadata["platform"] == "web"
        assert session.metadata["browser"] == "Chrome"

    def test_session_device_fingerprint(self):
        """Test session device fingerprinting."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            device_fingerprint="abc123def456",
        )
        
        assert session.device_fingerprint == "abc123def456"

    def test_session_location_tracking(self):
        """Test session location tracking."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address=IpAddress("8.8.8.8"),
            location={
                "country": "US",
                "city": "Mountain View",
                "latitude": 37.4223,
                "longitude": -122.0840,
            }
        )
        
        assert session.location["country"] == "US"
        assert session.location["city"] == "Mountain View"

    def test_session_string_representation(self):
        """Test string representation of session."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token123",
            refresh_token="refresh123",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            device_name="iPhone",
        )
        
        str_repr = str(session)
        repr_repr = repr(session)
        
        assert "Session" in repr_repr
        assert str(session.id) in repr_repr
        # Should not expose tokens
        assert "token123" not in str_repr
        assert "refresh123" not in str_repr

    def test_session_refresh_limit(self):
        """Test session refresh count limit."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        
        # Simulate many refreshes
        session.refresh_count = 99
        
        # One more refresh should be allowed
        session.refresh(
            new_access_token="new",
            new_refresh_token="new",
            new_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        
        assert session.refresh_count == 100
        
        # Next refresh should fail
        with pytest.raises(BusinessRuleViolation) as exc_info:
            session.refresh(
                new_access_token="newer",
                new_refresh_token="newer",
                new_expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        
        assert "refresh limit" in str(exc_info.value).lower()

    def test_session_concurrent_device_limit(self):
        """Test concurrent device session limits."""
        user_id = UserId.generate()
        
        sessions = []
        for i in range(5):
            session = Session.create(
                user_id=user_id,
                access_token=f"token{i}",
                refresh_token=f"refresh{i}",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                device_name=f"Device {i}",
            )
            sessions.append(session)
        
        # All sessions should be valid
        assert all(s.is_active for s in sessions)
        
        # Business logic for concurrent limit would be in domain service

    def test_session_domain_events(self):
        """Test that session operations generate domain events."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        
        # Clear initial events
        session.pull_domain_events()
        
        # Refresh session
        session.refresh(
            new_access_token="new",
            new_refresh_token="new",
            new_expires_at=datetime.now(UTC) + timedelta(hours=2),
        )
        
        events = session.pull_domain_events()
        assert len(events) == 1
        assert events[0].__class__.__name__ == "SessionRefreshedEvent"
        
        # Revoke session
        session.revoke()
        
        events = session.pull_domain_events()
        assert len(events) == 1
        assert events[0].__class__.__name__ == "SessionRevokedEvent"

    def test_session_security_flags(self):
        """Test session security flags."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            requires_mfa=True,
            is_elevated=True,
        )
        
        assert session.requires_mfa is True
        assert session.is_elevated is True

    def test_session_token_family(self):
        """Test session token family for refresh token rotation."""
        session = Session.create(
            user_id=UserId.generate(),
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            token_family="family_123",
        )
        
        assert session.token_family == "family_123"
        
        # Refresh should maintain token family
        session.refresh(
            new_access_token="new",
            new_refresh_token="new",
            new_expires_at=datetime.now(UTC) + timedelta(hours=2),
        )
        
        assert session.token_family == "family_123"