"""
User entity test data builder.

Provides fluent interface for creating User test data with unique values
to eliminate hardcoded test data and enable parallel test execution.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.security_stamp import SecurityStamp


class UserBuilder:
    """Fluent builder for User entities with unique test data."""
    
    def __init__(self):
        """Initialize builder with sensible defaults."""
        self._id = uuid.uuid4()
        self._email = Email(f"user_{uuid.uuid4().hex[:8]}@test.local")
        self._password_hash = PasswordHash.create_from_password("TestPass123!@#")
        self._security_stamp = SecurityStamp.generate_initial()
        self._is_active = True
        self._is_verified = True
        self._created_at = datetime.now(timezone.utc)
        self._updated_at = datetime.now(timezone.utc)
        
    def with_id(self, user_id: uuid.UUID) -> "UserBuilder":
        """Set specific user ID."""
        self._id = user_id
        return self
        
    def with_email(self, email: str) -> "UserBuilder":
        """Set specific email (will be made unique)."""
        unique_suffix = uuid.uuid4().hex[:6]
        local, domain = email.split("@", 1)
        unique_email = f"{local}_{unique_suffix}@{domain}"
        self._email = Email(unique_email)
        return self
        
    def with_password(self, password: str) -> "UserBuilder":
        """Set specific password."""
        self._password_hash = PasswordHash.create_from_password(password)
        return self
        
    def inactive(self) -> "UserBuilder":
        """Make user inactive."""
        self._is_active = False
        return self
        
    def unverified(self) -> "UserBuilder":
        """Make user unverified."""
        self._is_verified = False
        return self
        
    def verified(self) -> "UserBuilder":
        """Make user verified (default)."""
        self._is_verified = True
        return self
        
    def with_security_stamp(self, stamp: Optional[str] = None) -> "UserBuilder":
        """Set specific security stamp or generate new one."""
        if stamp:
            self._security_stamp = SecurityStamp(stamp)
        else:
            self._security_stamp = SecurityStamp.generate_initial()
        return self
        
    def build(self) -> User:
        """Build the User entity."""
        return User(
            id=self._id,
            email=self._email,
            password_hash=self._password_hash,
            security_stamp=self._security_stamp,
            is_active=self._is_active,
            is_verified=self._is_verified,
            created_at=self._created_at,
            updated_at=self._updated_at,
        )


class UserMother:
    """Object Mother pattern for common User scenarios."""
    
    @staticmethod
    def active_verified_user() -> User:
        """Create standard active, verified user."""
        return UserBuilder().build()
        
    @staticmethod
    def inactive_user() -> User:
        """Create inactive user."""
        return UserBuilder().inactive().build()
        
    @staticmethod
    def unverified_user() -> User:
        """Create unverified user."""
        return UserBuilder().unverified().build()
        
    @staticmethod
    def admin_user() -> User:
        """Create admin user with admin email pattern."""
        return (UserBuilder()
                .with_email("admin@company.local")
                .build())
                
    @staticmethod
    def test_user_with_password(password: str) -> User:
        """Create user with specific password for auth tests."""
        return (UserBuilder()
                .with_password(password)
                .build())