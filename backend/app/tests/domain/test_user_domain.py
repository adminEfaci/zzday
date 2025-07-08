"""
User Domain Tests

Pure domain tests for User entity isolated from infrastructure.
Tests business rules and domain logic without external dependencies.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.security_stamp import SecurityStamp
from app.modules.identity.domain.exceptions import (
    InvalidEmailError,
    InvalidPasswordError,
    UserInactiveError,
    UserUnverifiedError,
)


@pytest.mark.unit
class TestUserDomainCreation:
    """Test user domain entity creation."""
    
    def test_create_user_with_valid_data(self):
        """Test creating user with valid data."""
        user_id = uuid4()
        email = Email("test@example.com")
        password_hash = PasswordHash.create_from_password("password123")
        security_stamp = SecurityStamp.generate_initial()
        
        user = User(
            id=user_id,
            email=email,
            password_hash=password_hash,
            security_stamp=security_stamp,
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.id == user_id
        assert user.email == email
        assert user.password_hash == password_hash
        assert user.security_stamp == security_stamp
        assert user.is_active is True
        assert user.is_verified is True
        assert user.is_admin is False
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
    
    def test_create_user_with_minimal_data(self):
        """Test creating user with minimal required data."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.email.value == "test@example.com"
        assert user.is_active is True
        assert user.is_verified is False
        assert user.is_admin is False
        assert user.name is None
        assert user.bio is None
        assert user.phone is None
        assert user.avatar_url is None
        assert user.timezone is None
        assert user.language is None
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert user.last_login_at is None
        assert user.last_password_change_at is None
        assert user.two_factor_enabled is False
        assert user.two_factor_secret is None
        assert user.backup_codes == []
        assert user.profile_data == {}
        assert user.preferences == {}
        assert user.metadata == {}


@pytest.mark.unit
class TestUserDomainBusinessRules:
    """Test user domain business rules."""
    
    def test_user_can_authenticate_when_active_and_verified(self):
        """Test user can authenticate when active and verified."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # User should be able to authenticate
        assert user.can_authenticate() is True
    
    def test_user_cannot_authenticate_when_inactive(self):
        """Test user cannot authenticate when inactive."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=False,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.can_authenticate() is False
    
    def test_user_cannot_authenticate_when_unverified(self):
        """Test user cannot authenticate when unverified."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.can_authenticate() is False
    
    def test_user_cannot_authenticate_when_locked(self):
        """Test user cannot authenticate when locked."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            locked_until=datetime.now(timezone.utc) + timedelta(hours=1),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.can_authenticate() is False
    
    def test_user_can_authenticate_when_lock_expired(self):
        """Test user can authenticate when lock has expired."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            locked_until=datetime.now(timezone.utc) - timedelta(hours=1),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.can_authenticate() is True


@pytest.mark.unit
class TestUserDomainOperations:
    """Test user domain operations."""
    
    def test_verify_user_email(self):
        """Test verifying user email."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.is_verified is False
        
        user.verify_email()
        
        assert user.is_verified is True
        assert user.email_verified_at is not None
    
    def test_activate_user(self):
        """Test activating user."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=False,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.is_active is False
        
        user.activate()
        
        assert user.is_active is True
    
    def test_deactivate_user(self):
        """Test deactivating user."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.is_active is True
        
        user.deactivate()
        
        assert user.is_active is False
    
    def test_change_password(self):
        """Test changing user password."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        old_password_hash = user.password_hash
        old_security_stamp = user.security_stamp
        
        new_password = "new_password123"
        user.change_password(new_password)
        
        assert user.password_hash != old_password_hash
        assert user.security_stamp != old_security_stamp
        assert user.last_password_change_at is not None
    
    def test_update_profile(self):
        """Test updating user profile."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        user.update_profile(
            name="John Doe",
            bio="Software Developer",
            phone="+1234567890",
            timezone="UTC",
            language="en"
        )
        
        assert user.name == "John Doe"
        assert user.bio == "Software Developer"
        assert user.phone == "+1234567890"
        assert user.timezone == "UTC"
        assert user.language == "en"
    
    def test_record_successful_login(self):
        """Test recording successful login."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.failed_login_attempts == 0
        assert user.last_login_at is None
        
        user.record_successful_login()
        
        assert user.failed_login_attempts == 0
        assert user.last_login_at is not None
    
    def test_record_failed_login(self):
        """Test recording failed login."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        
        user.record_failed_login()
        
        assert user.failed_login_attempts == 1
        assert user.locked_until is None
    
    def test_user_locked_after_max_failed_attempts(self):
        """Test user is locked after max failed attempts."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Record max failed attempts
        for i in range(5):
            user.record_failed_login()
        
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None
        assert user.locked_until > datetime.now(timezone.utc)
    
    def test_unlock_user(self):
        """Test unlocking user."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            locked_until=datetime.now(timezone.utc) + timedelta(hours=1),
            failed_login_attempts=5,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user.locked_until is not None
        assert user.failed_login_attempts == 5
        
        user.unlock()
        
        assert user.locked_until is None
        assert user.failed_login_attempts == 0


@pytest.mark.unit
class TestUserDomainValidation:
    """Test user domain validation rules."""
    
    def test_user_cannot_have_invalid_email(self):
        """Test user cannot have invalid email."""
        with pytest.raises(InvalidEmailError):
            User(
                id=uuid4(),
                email=Email("invalid-email"),
                password_hash=PasswordHash.create_from_password("password123"),
                security_stamp=SecurityStamp.generate_initial(),
                is_active=True,
                is_verified=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
    
    def test_user_cannot_have_weak_password(self):
        """Test user cannot have weak password."""
        with pytest.raises(InvalidPasswordError):
            User(
                id=uuid4(),
                email=Email("test@example.com"),
                password_hash=PasswordHash.create_from_password("weak"),
                security_stamp=SecurityStamp.generate_initial(),
                is_active=True,
                is_verified=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
    
    def test_user_requires_security_stamp(self):
        """Test user requires security stamp."""
        with pytest.raises(ValueError):
            User(
                id=uuid4(),
                email=Email("test@example.com"),
                password_hash=PasswordHash.create_from_password("password123"),
                security_stamp=None,
                is_active=True,
                is_verified=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
    
    def test_user_requires_valid_timestamps(self):
        """Test user requires valid timestamps."""
        with pytest.raises(ValueError):
            User(
                id=uuid4(),
                email=Email("test@example.com"),
                password_hash=PasswordHash.create_from_password("password123"),
                security_stamp=SecurityStamp.generate_initial(),
                is_active=True,
                is_verified=True,
                created_at=None,
                updated_at=datetime.now(timezone.utc)
            )


@pytest.mark.unit
class TestUserDomainEquality:
    """Test user domain equality and identity."""
    
    def test_users_with_same_id_are_equal(self):
        """Test users with same ID are equal."""
        user_id = uuid4()
        
        user1 = User(
            id=user_id,
            email=Email("test1@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        user2 = User(
            id=user_id,
            email=Email("test2@example.com"),
            password_hash=PasswordHash.create_from_password("password456"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=False,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user1 == user2
        assert hash(user1) == hash(user2)
    
    def test_users_with_different_id_are_not_equal(self):
        """Test users with different IDs are not equal."""
        user1 = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        user2 = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert user1 != user2
        assert hash(user1) != hash(user2)
    
    def test_user_string_representation(self):
        """Test user string representation."""
        user = User(
            id=uuid4(),
            email=Email("test@example.com"),
            password_hash=PasswordHash.create_from_password("password123"),
            security_stamp=SecurityStamp.generate_initial(),
            is_active=True,
            is_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        user_str = str(user)
        assert "User" in user_str
        assert "test@example.com" in user_str
        assert str(user.id) in user_str