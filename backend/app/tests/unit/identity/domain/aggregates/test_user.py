"""
Comprehensive unit tests for User aggregate.

Tests cover:
- User creation and initialization
- State transitions
- Business rule enforcement
- Event generation
- Invariant protection
"""

import pytest
from datetime import datetime, timedelta, UTC
from uuid import uuid4

from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.phone_number import PhoneNumber
from app.modules.identity.domain.value_objects.user_id import UserId
from app.modules.identity.domain.value_objects.user_profile import UserProfile
from app.modules.identity.domain.value_objects.security_stamp import SecurityStamp
from app.modules.identity.domain.enums import UserStatus, UserType
from app.modules.identity.domain.errors import DomainError, BusinessRuleViolation
from app.modules.identity.domain.events.user_events import (
    UserCreatedEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
    UserLockedEvent,
    UserUnlockedEvent,
    UserEmailChangedEvent,
    UserPasswordChangedEvent,
    UserProfileUpdatedEvent,
    UserDeletedEvent,
)


class TestUserAggregate:
    """Test suite for User aggregate."""

    def test_create_user_with_minimal_data(self):
        """Test creating user with minimal required data."""
        email = Email("user@example.com")
        username = Username("johndoe")
        password_hash = PasswordHash.from_password("SecurePass123!")
        
        user = User.create(
            email=email,
            username=username,
            password_hash=password_hash,
        )
        
        assert isinstance(user.id, UserId)
        assert user.email == email
        assert user.username == username
        assert user.password_hash == password_hash
        assert user.status == UserStatus.PENDING_ACTIVATION
        assert user.type == UserType.STANDARD
        assert not user.is_active
        assert not user.email_verified
        assert user.created_at <= datetime.now(UTC)
        assert user.updated_at <= datetime.now(UTC)
        
        # Check event generation
        events = user.pull_domain_events()
        assert len(events) == 1
        assert isinstance(events[0], UserCreatedEvent)
        assert events[0].user_id == user.id
        assert events[0].email == email.value
        assert events[0].username == username.value

    def test_create_user_with_full_data(self):
        """Test creating user with all optional data."""
        email = Email("user@example.com")
        username = Username("johndoe")
        password_hash = PasswordHash.from_password("SecurePass123!")
        phone = PhoneNumber("+1234567890")
        profile = UserProfile(
            first_name="John",
            last_name="Doe",
            display_name="John Doe",
            bio="Software developer",
            avatar_url="https://example.com/avatar.jpg",
            timezone="America/New_York",
            locale="en_US",
            date_of_birth=datetime(1990, 1, 1).date()
        )
        
        user = User.create(
            email=email,
            username=username,
            password_hash=password_hash,
            phone_number=phone,
            profile=profile,
            type=UserType.PREMIUM,
        )
        
        assert user.phone_number == phone
        assert user.profile == profile
        assert user.type == UserType.PREMIUM

    def test_activate_user(self):
        """Test user activation flow."""
        user = self._create_test_user()
        assert user.status == UserStatus.PENDING_ACTIVATION
        assert not user.is_active
        
        user.activate()
        
        assert user.status == UserStatus.ACTIVE
        assert user.is_active
        assert user.email_verified
        assert user.activated_at is not None
        assert user.activated_at <= datetime.now(UTC)
        
        # Check event generation
        events = user.pull_domain_events()
        assert any(isinstance(e, UserActivatedEvent) for e in events)

    def test_cannot_activate_already_active_user(self):
        """Test that activating an already active user raises error."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            user.activate()
        assert "already active" in str(exc_info.value).lower()

    def test_deactivate_user(self):
        """Test user deactivation flow."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        reason = "User requested account closure"
        user.deactivate(reason)
        
        assert user.status == UserStatus.INACTIVE
        assert not user.is_active
        assert user.deactivated_at is not None
        
        # Check event generation
        events = user.pull_domain_events()
        assert len(events) == 1
        assert isinstance(events[0], UserDeactivatedEvent)
        assert events[0].reason == reason

    def test_lock_user_account(self):
        """Test user account locking."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        reason = "Multiple failed login attempts"
        locked_until = datetime.now(UTC) + timedelta(hours=1)
        
        user.lock(reason, locked_until)
        
        assert user.is_locked
        assert user.locked_at is not None
        assert user.locked_until == locked_until
        assert user.lock_reason == reason
        
        # Check event generation
        events = user.pull_domain_events()
        assert len(events) == 1
        assert isinstance(events[0], UserLockedEvent)
        assert events[0].reason == reason
        assert events[0].locked_until == locked_until

    def test_unlock_user_account(self):
        """Test user account unlocking."""
        user = self._create_test_user()
        user.activate()
        user.lock("Test lock", datetime.now(UTC) + timedelta(hours=1))
        user.pull_domain_events()  # Clear events
        
        user.unlock()
        
        assert not user.is_locked
        assert user.locked_at is None
        assert user.locked_until is None
        assert user.lock_reason is None
        
        # Check event generation
        events = user.pull_domain_events()
        assert len(events) == 1
        assert isinstance(events[0], UserUnlockedEvent)

    def test_cannot_unlock_non_locked_user(self):
        """Test that unlocking a non-locked user raises error."""
        user = self._create_test_user()
        user.activate()
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            user.unlock()
        assert "not locked" in str(exc_info.value).lower()

    def test_change_email(self):
        """Test email change."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        old_email = user.email
        new_email = Email("newemail@example.com")
        
        user.change_email(new_email)
        
        assert user.email == new_email
        assert not user.email_verified  # Requires re-verification
        assert user.previous_email == old_email
        assert user.security_stamp != user._original_security_stamp
        
        # Check event generation
        events = user.pull_domain_events()
        assert any(isinstance(e, UserEmailChangedEvent) for e in events)
        email_event = next(e for e in events if isinstance(e, UserEmailChangedEvent))
        assert email_event.old_email == old_email.value
        assert email_event.new_email == new_email.value

    def test_cannot_change_to_same_email(self):
        """Test that changing to the same email raises error."""
        user = self._create_test_user()
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            user.change_email(user.email)
        assert "same as current" in str(exc_info.value).lower()

    def test_change_password(self):
        """Test password change."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        old_security_stamp = user.security_stamp
        new_password_hash = PasswordHash.from_password("NewSecurePass123!")
        
        user.change_password(new_password_hash)
        
        assert user.password_hash == new_password_hash
        assert user.password_changed_at is not None
        assert user.security_stamp != old_security_stamp
        
        # Check event generation
        events = user.pull_domain_events()
        assert any(isinstance(e, UserPasswordChangedEvent) for e in events)

    def test_update_profile(self):
        """Test profile update."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        new_profile = UserProfile(
            first_name="Jane",
            last_name="Smith",
            display_name="Jane Smith",
            bio="Updated bio",
            timezone="Europe/London",
            locale="en_GB"
        )
        
        user.update_profile(new_profile)
        
        assert user.profile == new_profile
        
        # Check event generation
        events = user.pull_domain_events()
        assert any(isinstance(e, UserProfileUpdatedEvent) for e in events)

    def test_verify_email(self):
        """Test email verification."""
        user = self._create_test_user()
        assert not user.email_verified
        
        user.verify_email()
        
        assert user.email_verified
        assert user.email_verified_at is not None

    def test_add_login_attempt(self):
        """Test tracking login attempts."""
        user = self._create_test_user()
        user.activate()
        
        # Successful login
        user.record_successful_login("192.168.1.1", "Mozilla/5.0")
        
        assert user.last_login_at is not None
        assert user.last_login_ip == "192.168.1.1"
        assert user.login_count == 1
        assert user.failed_login_count == 0
        
        # Failed login
        user.record_failed_login("192.168.1.2", "Mozilla/5.0")
        
        assert user.failed_login_count == 1
        assert user.last_failed_login_at is not None

    def test_auto_lock_after_max_failed_attempts(self):
        """Test automatic locking after maximum failed login attempts."""
        user = self._create_test_user()
        user.activate()
        
        # Record multiple failed attempts
        for i in range(5):  # Assuming 5 is the max
            user.record_failed_login(f"192.168.1.{i}", "Mozilla/5.0")
        
        assert user.is_locked
        assert user.lock_reason == "Too many failed login attempts"

    def test_delete_user(self):
        """Test user deletion (soft delete)."""
        user = self._create_test_user()
        user.activate()
        user.pull_domain_events()  # Clear events
        
        user.delete()
        
        assert user.status == UserStatus.DELETED
        assert user.deleted_at is not None
        assert user.is_deleted
        
        # Check event generation
        events = user.pull_domain_events()
        assert any(isinstance(e, UserDeletedEvent) for e in events)

    def test_cannot_modify_deleted_user(self):
        """Test that deleted users cannot be modified."""
        user = self._create_test_user()
        user.activate()
        user.delete()
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            user.change_email(Email("new@example.com"))
        assert "deleted" in str(exc_info.value).lower()
        
        with pytest.raises(BusinessRuleViolation):
            user.update_profile(UserProfile(first_name="New"))
        
        with pytest.raises(BusinessRuleViolation):
            user.deactivate("Test")

    def test_user_roles_management(self):
        """Test user role assignment and removal."""
        user = self._create_test_user()
        user.activate()
        
        role_id1 = uuid4()
        role_id2 = uuid4()
        
        # Add roles
        user.assign_role(role_id1)
        user.assign_role(role_id2)
        
        assert len(user.role_ids) == 2
        assert role_id1 in user.role_ids
        assert role_id2 in user.role_ids
        
        # Remove role
        user.remove_role(role_id1)
        
        assert len(user.role_ids) == 1
        assert role_id1 not in user.role_ids
        assert role_id2 in user.role_ids

    def test_cannot_assign_duplicate_role(self):
        """Test that assigning the same role twice raises error."""
        user = self._create_test_user()
        role_id = uuid4()
        
        user.assign_role(role_id)
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            user.assign_role(role_id)
        assert "already assigned" in str(exc_info.value).lower()

    def test_user_permissions_check(self):
        """Test user permission checking."""
        user = self._create_test_user()
        user.activate()
        
        # Direct permission
        user.grant_permission("users.read")
        assert user.has_permission("users.read")
        assert not user.has_permission("users.write")
        
        # Revoke permission
        user.revoke_permission("users.read")
        assert not user.has_permission("users.read")

    def test_user_tags_management(self):
        """Test user tags for categorization."""
        user = self._create_test_user()
        
        user.add_tag("vip")
        user.add_tag("beta-tester")
        
        assert len(user.tags) == 2
        assert "vip" in user.tags
        assert "beta-tester" in user.tags
        
        user.remove_tag("vip")
        
        assert len(user.tags) == 1
        assert "vip" not in user.tags

    def test_user_metadata(self):
        """Test user metadata storage."""
        user = self._create_test_user()
        
        user.set_metadata("preference.theme", "dark")
        user.set_metadata("preference.language", "en")
        
        assert user.get_metadata("preference.theme") == "dark"
        assert user.get_metadata("preference.language") == "en"
        assert user.get_metadata("non.existent") is None
        
        user.remove_metadata("preference.theme")
        assert user.get_metadata("preference.theme") is None

    def test_user_equality(self):
        """Test user equality based on ID."""
        user1 = self._create_test_user()
        user2 = self._create_test_user()
        
        # Same ID
        user3 = User(
            id=user1.id,
            email=Email("different@example.com"),
            username=Username("different"),
            password_hash=user1.password_hash,
            status=UserStatus.ACTIVE,
            type=UserType.STANDARD,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert user1 != user2  # Different IDs
        assert user1 == user3  # Same ID
        assert user1 != "not a user"

    def test_user_repr(self):
        """Test user representation."""
        user = self._create_test_user()
        repr_str = repr(user)
        
        assert "User" in repr_str
        assert str(user.id) in repr_str
        assert user.username.value in repr_str

    def test_user_invariants(self):
        """Test user aggregate invariants are protected."""
        user = self._create_test_user()
        
        # Cannot have both active and locked status
        user.activate()
        user.lock("Test", datetime.now(UTC) + timedelta(hours=1))
        assert user.status == UserStatus.ACTIVE
        assert user.is_locked
        
        # Cannot delete locked user without unlocking
        with pytest.raises(BusinessRuleViolation):
            user.delete()
        
        user.unlock()
        user.delete()  # Should work now

    def test_user_to_dict(self):
        """Test user serialization to dictionary."""
        user = self._create_test_user()
        user_dict = user.to_dict()
        
        assert user_dict["id"] == str(user.id)
        assert user_dict["email"] == user.email.value
        assert user_dict["username"] == user.username.value
        assert user_dict["status"] == user.status.value
        assert user_dict["type"] == user.type.value
        assert "password_hash" not in user_dict  # Should not expose

    def test_user_security_stamp_regeneration(self):
        """Test security stamp is regenerated on security-sensitive changes."""
        user = self._create_test_user()
        original_stamp = user.security_stamp
        
        # Email change regenerates stamp
        user.change_email(Email("new@example.com"))
        assert user.security_stamp != original_stamp
        
        # Password change regenerates stamp
        new_stamp = user.security_stamp
        user.change_password(PasswordHash.from_password("NewPass123!"))
        assert user.security_stamp != new_stamp

    # Helper methods
    
    def _create_test_user(self) -> User:
        """Create a test user with default values."""
        return User.create(
            email=Email("test@example.com"),
            username=Username("testuser"),
            password_hash=PasswordHash.from_password("TestPass123!"),
        )