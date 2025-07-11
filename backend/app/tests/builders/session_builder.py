"""
Session entity test data builder.

Provides fluent interface for creating Session test data.
"""

import uuid
from datetime import UTC, datetime, timedelta

from app.modules.identity.domain.entities.session import Session
from app.modules.identity.domain.value_objects.ip_address import IpAddress


class SessionBuilder:
    """Fluent builder for Session entities with unique test data."""
    
    def __init__(self):
        """Initialize builder with sensible defaults."""
        self._id = uuid.uuid4()
        self._user_id = uuid.uuid4()
        self._ip_address = IpAddress("192.168.1.100")
        self._user_agent = "Mozilla/5.0 (Test Browser)"
        self._device_id = f"device_{uuid.uuid4().hex[:8]}"
        self._is_active = True
        self._created_at = datetime.now(UTC)
        self._expires_at = datetime.now(UTC) + timedelta(hours=24)
        self._last_accessed_at = datetime.now(UTC)
        
    def with_user_id(self, user_id: uuid.UUID) -> "SessionBuilder":
        """Set specific user ID."""
        self._user_id = user_id
        return self
        
    def with_ip(self, ip: str) -> "SessionBuilder":
        """Set specific IP address."""
        self._ip_address = IpAddress(ip)
        return self
        
    def with_device_id(self, device_id: str) -> "SessionBuilder":
        """Set specific device ID."""
        self._device_id = device_id
        return self
        
    def expired(self) -> "SessionBuilder":
        """Make session expired."""
        self._expires_at = datetime.now(UTC) - timedelta(hours=1)
        return self
        
    def inactive(self) -> "SessionBuilder":
        """Make session inactive."""
        self._is_active = False
        return self
        
    def with_duration(self, hours: int) -> "SessionBuilder":
        """Set session duration."""
        self._expires_at = self._created_at + timedelta(hours=hours)
        return self
        
    def build(self) -> Session:
        """Build the Session entity."""
        return Session(
            id=self._id,
            user_id=self._user_id,
            ip_address=self._ip_address,
            user_agent=self._user_agent,
            device_id=self._device_id,
            is_active=self._is_active,
            created_at=self._created_at,
            expires_at=self._expires_at,
            last_accessed_at=self._last_accessed_at,
        )


class SessionMother:
    """Object Mother pattern for common Session scenarios."""
    
    @staticmethod
    def active_session(user_id: uuid.UUID | None = None) -> Session:
        """Create active session."""
        builder = SessionBuilder()
        if user_id:
            builder = builder.with_user_id(user_id)
        return builder.build()
        
    @staticmethod
    def expired_session(user_id: uuid.UUID | None = None) -> Session:
        """Create expired session."""
        builder = SessionBuilder().expired()
        if user_id:
            builder = builder.with_user_id(user_id)
        return builder.build()
        
    @staticmethod
    def mobile_session(user_id: uuid.UUID | None = None) -> Session:
        """Create mobile session."""
        builder = (SessionBuilder()
                  .with_device_id("mobile_device_123")
                  .with_ip("10.0.0.1"))
        if user_id:
            builder = builder.with_user_id(user_id)
        return builder.build()