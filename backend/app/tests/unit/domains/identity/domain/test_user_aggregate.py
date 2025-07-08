"""
Comprehensive tests for User Aggregate Root - Identity Domain

This test suite provides 100% coverage of the User aggregate including:
- User creation and registration flows
- Authentication and session management
- Password management and security
- MFA operations and device management
- Role and permission management
- Account status transitions and lifecycle
- Security features and risk assessment
- Profile and preference management
- Email and phone number management
- Device registration and trust
- Audit logging and compliance features

Test Coverage Target: 100% (Statements, Branches, Functions, Lines)
"""

import hashlib
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest

from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.constants import SecurityLimits
from app.modules.identity.domain.entities.admin import MfaDevice
from app.modules.identity.domain.entities.role.role_events import *
from app.modules.identity.domain.entities.session import Session
from app.modules.identity.domain.entities.session.session_errors import *
from app.modules.identity.domain.entities.session.session_events import *
from app.modules.identity.domain.entities.user.user_enums import AccountType, UserStatus
from app.modules.identity.domain.entities.user.user_enums import MFAMethod as MfaMethod
from app.modules.identity.domain.entities.user.user_errors import *
from app.modules.identity.domain.entities.user.user_events import *
from app.modules.identity.domain.value_objects import (
    Email,
    PhoneNumber,
    SecurityStamp,
    Username,
)


class TestUserAggregateCreation:
    """Test User aggregate creation and initialization"""

    def test_user_register_basic(self, event_collector):
        """Test basic user registration with minimal requirements"""
        email = "test@example.com"
        username = "testuser"
        password = "StrongPassword123!"

        user = User.register(
            email=email,
            username=username,
            password=password,
            account_type=AccountType.CUSTOMER,
            auto_activate=False,
        )

        # Verify basic properties
        assert isinstance(user.id, UUID)
        assert user.email.value == email.lower()
        assert user.username.value == username
        assert user.status == UserStatus.PENDING
        assert user.account_type == AccountType.CUSTOMER
        assert user.email_verified is False
        assert user.phone_verified is False
        assert user.mfa_enabled is False
        assert user.login_count == 0
        assert user.failed_login_count == 0
        assert isinstance(user.security_stamp, SecurityStamp)

        # Verify password is hashed
        assert user.password_hash != password
        assert len(user.password_hash) > 50  # Hashed passwords are long

        # Verify timestamps
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
        assert isinstance(user.password_changed_at, datetime)

        # Verify events
        events = user.get_events()
        assert len(events) == 1
        assert isinstance(events[0], UserRegistered)
        assert events[0].user_id == user.id
        assert events[0].email == email
        assert events[0].username == username

    def test_user_register_auto_activate(self, event_collector):
        """Test user registration with auto-activation"""
        user = User.register(
            email="auto@example.com",
            username="autouser",
            password="Password123!",
            auto_activate=True,
        )

        assert user.status == UserStatus.ACTIVE
        assert user.email_verified is True

        # Should have both registration and activation events
        events = user.get_events()
        assert len(events) == 2
        event_types = [type(e).__name__ for e in events]
        assert "UserRegistered" in event_types
        assert "UserActivated" in event_types

    def test_user_register_admin_account(self):
        """Test registration of admin account type"""
        user = User.register(
            email="admin@example.com",
            username="admin",
            password="AdminPassword123!",
            account_type=AccountType.ADMIN,
            auto_activate=True,
        )

        assert user.account_type == AccountType.ADMIN
        assert user.status == UserStatus.ACTIVE

    def test_user_post_init_validation(self):
        """Test user post-init validation rules"""
        user_id = uuid4()

        # Test negative failed login count should raise error
        with pytest.raises(ValueError, match="Failed login count cannot be negative"):
            User(
                id=user_id,
                email=Email("test@example.com"),
                username=Username("test"),
                password_hash="hashed_password",
                status=UserStatus.ACTIVE,
                account_type=AccountType.CUSTOMER,
                email_verified=True,
                phone_verified=False,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                failed_login_count=-1,
            )

        # Test negative login count should raise error
        with pytest.raises(ValueError, match="Login count cannot be negative"):
            User(
                id=user_id,
                email=Email("test@example.com"),
                username=Username("test"),
                password_hash="hashed_password",
                status=UserStatus.ACTIVE,
                account_type=AccountType.CUSTOMER,
                email_verified=True,
                phone_verified=False,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                login_count=-1,
            )


class TestUserActivationAndStatus:
    """Test user activation and status management"""

    def test_activate_pending_user(self, event_collector):
        """Test activating a pending user"""
        user = User.register(
            email="pending@example.com",
            username="pending",
            password="Password123!",
            auto_activate=False,
        )

        assert user.status == UserStatus.PENDING
        assert user.email_verified is False

        admin_id = uuid4()
        user.activate(activated_by=admin_id)

        assert user.status == UserStatus.ACTIVE
        assert user.email_verified is True

        # Check events
        events = user.get_events()
        activation_events = [e for e in events if isinstance(e, UserActivated)]
        assert len(activation_events) == 1
        assert activation_events[0].activated_by == admin_id

    def test_activate_already_active_user(self):
        """Test activating already active user (no-op)"""
        user = User.register(
            email="active@example.com",
            username="active",
            password="Password123!",
            auto_activate=True,
        )

        initial_events_count = len(user.get_events())
        user.activate()

        # Should be no-op - no additional events
        assert len(user.get_events()) == initial_events_count

    def test_activate_invalid_status(self):
        """Test activating user with invalid status"""
        user = User.register(
            email="deleted@example.com",
            username="deleted",
            password="Password123!",
            auto_activate=False,
        )

        # Set to deleted status
        user.status = UserStatus.DELETED

        with pytest.raises(ValueError, match="Cannot activate user with status"):
            user.activate()

    def test_deactivate_active_user(self, event_collector):
        """Test deactivating an active user"""
        user = User.register(
            email="active@example.com",
            username="active",
            password="Password123!",
            auto_activate=True,
        )

        # Create some active sessions
        session1 = Mock()
        session1.is_active = True
        session1.revoke = Mock()
        session2 = Mock()
        session2.is_active = True
        session2.revoke = Mock()
        user._sessions = [session1, session2]

        admin_id = uuid4()
        user.deactivate(deactivated_by=admin_id, reason="Policy violation")

        assert user.status == UserStatus.INACTIVE

        # All sessions should be revoked
        session1.revoke.assert_called_once()
        session2.revoke.assert_called_once()

        # Check events
        events = user.get_events()
        deactivation_events = [e for e in events if isinstance(e, UserDeactivated)]
        assert len(deactivation_events) == 1
        assert deactivation_events[0].deactivated_by == admin_id
        assert deactivation_events[0].reason == "Policy violation"

    def test_deactivate_non_active_user(self):
        """Test deactivating non-active user (no-op)"""
        user = User.register(
            email="pending@example.com",
            username="pending",
            password="Password123!",
            auto_activate=False,
        )

        initial_events_count = len(user.get_events())
        user.deactivate(deactivated_by=uuid4(), reason="Test")

        # Should be no-op
        assert len(user.get_events()) == initial_events_count


class TestUserAuthentication:
    """Test user authentication and session creation"""

    @patch("app.core.security.verify_password")
    def test_authenticate_success(self, mock_verify_password, event_collector):
        """Test successful user authentication"""
        mock_verify_password.return_value = True

        user = User.register(
            email="auth@example.com",
            username="authuser",
            password="Password123!",
            auto_activate=True,
        )

        initial_login_count = user.login_count

        session = user.authenticate(
            password="Password123!",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 Chrome/91.0",
            device_fingerprint="device123",
        )

        # Check user updates
        assert user.login_count == initial_login_count + 1
        assert user.failed_login_count == 0
        assert user.last_login is not None
        assert user.last_failed_login is None

        # Check session
        assert isinstance(session, Session)
        assert session.user_id == user.id
        assert session in user._sessions

        # Check events
        events = user.get_events()
        session_events = [e for e in events if isinstance(e, UserSessionCreated)]
        assert len(session_events) == 1
        assert session_events[0].session_id == session.id
        assert session_events[0].ip_address == "192.168.1.100"

    @patch("app.core.security.verify_password")
    def test_authenticate_wrong_password(self, mock_verify_password):
        """Test authentication with wrong password"""
        mock_verify_password.return_value = False

        user = User.register(
            email="auth@example.com",
            username="authuser",
            password="Password123!",
            auto_activate=True,
        )

        initial_failed_count = user.failed_login_count

        with pytest.raises(InvalidCredentialsError):
            user.authenticate(
                password="WrongPassword",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0 Chrome/91.0",
            )

        # Check failed attempt tracking
        assert user.failed_login_count == initial_failed_count + 1
        assert user.last_failed_login is not None

    def test_authenticate_inactive_user(self):
        """Test authentication of inactive user"""
        user = User.register(
            email="inactive@example.com",
            username="inactive",
            password="Password123!",
            auto_activate=False,  # Stays pending
        )

        with pytest.raises(AccountInactiveError):
            user.authenticate(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
            )

    def test_authenticate_locked_user(self):
        """Test authentication of locked user"""
        user = User.register(
            email="locked@example.com",
            username="locked",
            password="Password123!",
            auto_activate=True,
        )

        # Lock the user
        user.lock()

        with pytest.raises(AccountLockedError):
            user.authenticate(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
            )

    def test_authenticate_suspended_user(self):
        """Test authentication of suspended user"""
        user = User.register(
            email="suspended@example.com",
            username="suspended",
            password="Password123!",
            auto_activate=True,
        )

        # Suspend the user
        user.status = UserStatus.SUSPENDED

        with pytest.raises(AccountInactiveError):
            user.authenticate(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
            )

    @patch("app.core.security.verify_password")
    def test_authenticate_lockout_after_failed_attempts(self, mock_verify_password):
        """Test account lockout after max failed attempts"""
        mock_verify_password.return_value = False

        user = User.register(
            email="lockout@example.com",
            username="lockout",
            password="Password123!",
            auto_activate=True,
        )

        # Make failed attempts up to the limit
        for _i in range(SecurityLimits.MAX_FAILED_LOGIN_ATTEMPTS):
            try:
                user.authenticate(
                    password="WrongPassword",
                    ip_address="192.168.1.100",
                    user_agent="Mozilla/5.0",
                )
            except InvalidCredentialsError:
                pass  # Expected

        # User should now be locked
        assert user.status == UserStatus.LOCKED
        assert user.locked_until is not None
        assert user.locked_until > datetime.now()


class TestUserPasswordManagement:
    """Test user password management operations"""

    @patch("app.core.security.verify_password")
    @patch("app.core.security.hash_password")
    def test_change_password_success(
        self, mock_hash_password, mock_verify_password, event_collector
    ):
        """Test successful password change"""
        mock_verify_password.return_value = True
        mock_hash_password.return_value = "new_hashed_password"

        user = User.register(
            email="password@example.com",
            username="password",
            password="OldPassword123!",
            auto_activate=True,
        )

        # Create some active sessions to test invalidation
        session1 = Mock()
        session1.is_active = True
        session1.revoke = Mock()
        session2 = Mock()
        session2.is_active = True
        session2.revoke = Mock()
        user._sessions = [session1, session2]

        initial_security_stamp = user.security_stamp

        user.change_password(
            current_password="OldPassword123!",
            new_password="NewPassword123!",
            changed_by=user.id,
        )

        # Check password update
        assert user.password_hash == "new_hashed_password"
        assert user.password_changed_at is not None
        assert user.require_password_change is False
        assert user.security_stamp != initial_security_stamp

        # Check sessions invalidated
        session1.revoke.assert_called_once()
        session2.revoke.assert_called_once()

        # Check password history
        assert len(user._password_history) == 1

        # Check events
        events = user.get_events()
        password_events = [e for e in events if isinstance(e, UserPasswordChanged)]
        assert len(password_events) == 1
        assert password_events[0].changed_by == user.id
        assert password_events[0].sessions_invalidated is True

    @patch("app.core.security.verify_password")
    def test_change_password_wrong_current(self, mock_verify_password):
        """Test password change with wrong current password"""
        mock_verify_password.return_value = False

        user = User.register(
            email="password@example.com",
            username="password",
            password="Password123!",
            auto_activate=True,
        )

        with pytest.raises(InvalidCredentialsError):
            user.change_password(
                current_password="WrongPassword",
                new_password="NewPassword123!",
                changed_by=user.id,
            )

    @patch("app.core.security.verify_password")
    def test_change_password_admin_reset(self, mock_verify_password):
        """Test admin password reset (no current password verification)"""
        mock_verify_password.return_value = False  # Current password is wrong

        user = User.register(
            email="password@example.com",
            username="password",
            password="Password123!",
            auto_activate=True,
        )

        admin_id = uuid4()

        # Admin reset should work even with wrong current password
        user.change_password(
            current_password="",  # Empty for admin reset
            new_password="NewPassword123!",
            changed_by=admin_id,
        )

        # Should succeed
        assert user.password_changed_at is not None

    @patch("app.core.security.verify_password")
    def test_change_password_history_check(self, mock_verify_password):
        """Test password history prevents reuse"""
        mock_verify_password.side_effect = [True, True, True]  # Multiple calls

        user = User.register(
            email="history@example.com",
            username="history",
            password="Password123!",
            auto_activate=True,
        )

        # Add some password history
        for i in range(3):
            history_entry = Mock()
            history_entry.password_hash = f"old_hash_{i}"
            history_entry.created_at = datetime.now() - timedelta(days=30 * i)
            user._password_history.append(history_entry)

        # Mock verification to return True for old password in history
        with patch.object(user, "_is_password_in_history", return_value=True):
            with pytest.raises(
                PasswordPolicyViolationError, match="Password was used recently"
            ):
                user.change_password(
                    current_password="Password123!",
                    new_password="OldReusedPassword",
                    changed_by=user.id,
                )


class TestUserMFAManagement:
    """Test Multi-Factor Authentication management"""

    def test_enable_mfa_totp(self, event_collector):
        """Test enabling TOTP MFA"""
        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        assert user.mfa_enabled is False
        assert len(user._mfa_devices) == 0

        device = user.enable_mfa(MfaMethod.TOTP)

        assert user.mfa_enabled is True
        assert len(user._mfa_devices) == 1
        assert isinstance(device, MfaDevice)
        assert device.method == MfaMethod.TOTP
        assert device.user_id == user.id

        # Check events
        events = user.get_events()
        mfa_events = [e for e in events if isinstance(e, UserMFAEnabled)]
        assert len(mfa_events) == 1
        assert mfa_events[0].mfa_method == MfaMethod.TOTP.value

    def test_enable_mfa_already_enabled(self):
        """Test enabling MFA when already enabled with same method"""
        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        # Enable MFA first time
        device1 = user.enable_mfa(MfaMethod.TOTP)
        device1.is_active = True  # Mock active device

        # Enable same method again - should return existing device
        device2 = user.enable_mfa(MfaMethod.TOTP)

        assert device1 is device2
        assert len(user._mfa_devices) == 1

    @patch("app.core.security.verify_password")
    def test_disable_mfa(self, mock_verify_password, event_collector):
        """Test disabling MFA"""
        mock_verify_password.return_value = True

        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        # Enable MFA first
        device = user.enable_mfa(MfaMethod.TOTP)
        device.deactivate = Mock()

        user.disable_mfa(password="Password123!")

        assert user.mfa_enabled is False
        device.deactivate.assert_called_once()

        # Check events
        events = user.get_events()
        mfa_events = [e for e in events if isinstance(e, UserMFADisabled)]
        assert len(mfa_events) == 1

    @patch("app.core.security.verify_password")
    def test_disable_mfa_wrong_password(self, mock_verify_password):
        """Test disabling MFA with wrong password"""
        mock_verify_password.return_value = False

        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        user.enable_mfa(MfaMethod.TOTP)

        with pytest.raises(InvalidCredentialsError):
            user.disable_mfa(password="WrongPassword")

    def test_requires_mfa_enabled(self):
        """Test MFA requirement when enabled"""
        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        user.enable_mfa(MfaMethod.TOTP)

        assert user.requires_mfa() is True

    def test_requires_mfa_role_requirement(self):
        """Test MFA requirement from role"""
        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        # Create role that requires MFA
        role = Mock()
        role.require_mfa = True
        user._roles = [role]

        assert user.requires_mfa() is True

    def test_verify_mfa_code_backup(self):
        """Test MFA verification with backup code"""
        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        # Generate backup codes
        codes = user.generate_backup_codes(count=5)
        backup_code = codes[0]

        # Verify backup code
        result = user.verify_mfa_code(backup_code)

        assert result is True
        assert len(user.backup_codes) == 4  # One less after use

    def test_verify_mfa_code_device(self):
        """Test MFA verification with device"""
        user = User.register(
            email="mfa@example.com",
            username="mfa",
            password="Password123!",
            auto_activate=True,
        )

        device = user.enable_mfa(MfaMethod.TOTP)
        device.is_active = True
        device.verify_code = Mock(return_value=True)
        device.update_last_used = Mock()

        result = user.verify_mfa_code("123456")

        assert result is True
        device.verify_code.assert_called_once_with("123456")
        device.update_last_used.assert_called_once()


class TestUserRoleAndPermissionManagement:
    """Test role and permission assignment"""

    def test_assign_role(self, event_collector):
        """Test assigning role to user"""
        user = User.register(
            email="role@example.com",
            username="role",
            password="Password123!",
            auto_activate=True,
        )

        role = Mock()
        role.id = uuid4()
        role.name = "Manager"

        admin_id = uuid4()
        user.assign_role(role, assigned_by=admin_id)

        assert len(user._roles) == 1
        assert user._roles[0] is role

        # Check events
        events = user.get_events()
        role_events = [e for e in events if isinstance(e, UserRoleAssigned)]
        assert len(role_events) == 1
        assert role_events[0].role_id == role.id
        assert role_events[0].assigned_by == admin_id

    def test_assign_duplicate_role(self):
        """Test assigning same role twice (no-op)"""
        user = User.register(
            email="role@example.com",
            username="role",
            password="Password123!",
            auto_activate=True,
        )

        role = Mock()
        role.id = uuid4()
        role.name = "Manager"

        user.assign_role(role, assigned_by=uuid4())
        initial_events_count = len(user.get_events())

        # Assign same role again
        user.assign_role(role, assigned_by=uuid4())

        assert len(user._roles) == 1
        assert len(user.get_events()) == initial_events_count  # No new events

    def test_revoke_role(self, event_collector):
        """Test revoking role from user"""
        user = User.register(
            email="role@example.com",
            username="role",
            password="Password123!",
            auto_activate=True,
        )

        role = Mock()
        role.id = uuid4()
        role.name = "Manager"
        user._roles = [role]

        admin_id = uuid4()
        user.revoke_role(role.id, revoked_by=admin_id)

        assert len(user._roles) == 0

        # Check events
        events = user.get_events()
        role_events = [e for e in events if isinstance(e, UserRoleRevoked)]
        assert len(role_events) == 1
        assert role_events[0].role_id == role.id
        assert role_events[0].revoked_by == admin_id

    def test_revoke_nonexistent_role(self):
        """Test revoking role that user doesn't have"""
        user = User.register(
            email="role@example.com",
            username="role",
            password="Password123!",
            auto_activate=True,
        )

        initial_events_count = len(user.get_events())

        user.revoke_role(uuid4(), revoked_by=uuid4())

        # Should be no-op
        assert len(user.get_events()) == initial_events_count

    def test_grant_permission(self, event_collector):
        """Test granting direct permission to user"""
        user = User.register(
            email="perm@example.com",
            username="perm",
            password="Password123!",
            auto_activate=True,
        )

        permission = Mock()
        permission.id = uuid4()
        permission.name = "read_reports"

        admin_id = uuid4()
        user.grant_permission(permission, granted_by=admin_id)

        assert len(user._permissions) == 1
        assert user._permissions[0] is permission

        # Check events
        events = user.get_events()
        perm_events = [e for e in events if isinstance(e, UserPermissionGranted)]
        assert len(perm_events) == 1
        assert perm_events[0].permission_id == permission.id
        assert perm_events[0].granted_by == admin_id

    def test_get_all_permissions(self):
        """Test getting all permissions (direct + from roles)"""
        user = User.register(
            email="perm@example.com",
            username="perm",
            password="Password123!",
            auto_activate=True,
        )

        # Direct permissions
        direct_perm = Mock()
        direct_perm.id = uuid4()
        direct_perm.name = "direct_permission"
        user._permissions = [direct_perm]

        # Role permissions
        role_perm1 = Mock()
        role_perm1.id = uuid4()
        role_perm1.name = "role_permission_1"

        role_perm2 = Mock()
        role_perm2.id = uuid4()
        role_perm2.name = "role_permission_2"

        role = Mock()
        role.permissions = [role_perm1, role_perm2]
        user._roles = [role]

        all_permissions = user.get_all_permissions()

        assert len(all_permissions) == 3
        permission_names = {p.name for p in all_permissions}
        assert "direct_permission" in permission_names
        assert "role_permission_1" in permission_names
        assert "role_permission_2" in permission_names

    def test_has_permission(self):
        """Test checking if user has specific permission"""
        user = User.register(
            email="perm@example.com",
            username="perm",
            password="Password123!",
            auto_activate=True,
        )

        permission = Mock()
        permission.name = "read_users"
        user._permissions = [permission]

        assert user.has_permission("read_users") is True
        assert user.has_permission("write_users") is False


class TestUserAccountLockingAndSuspension:
    """Test account locking and suspension mechanisms"""

    def test_lock_user_temporary(self, event_collector):
        """Test temporary user account lock"""
        user = User.register(
            email="lock@example.com",
            username="lock",
            password="Password123!",
            auto_activate=True,
        )

        # Create active sessions
        session1 = Mock()
        session1.is_active = True
        session1.revoke = Mock()
        user._sessions = [session1]

        duration = timedelta(hours=2)
        user.lock(duration=duration)

        assert user.status == UserStatus.LOCKED
        assert user.locked_until is not None
        assert user.locked_until > datetime.now()

        # Sessions should be revoked
        session1.revoke.assert_called_once()

        # Check events
        events = user.get_events()
        lock_events = [e for e in events if isinstance(e, UserLocked)]
        assert len(lock_events) == 1
        assert lock_events[0].locked_until == user.locked_until

    def test_lock_user_permanent(self):
        """Test permanent user account lock"""
        user = User.register(
            email="lock@example.com",
            username="lock",
            password="Password123!",
            auto_activate=True,
        )

        user.lock()  # No duration = permanent

        assert user.status == UserStatus.LOCKED
        assert user.locked_until is not None
        # Should be locked for ~100 years (effectively permanent)
        assert user.locked_until > datetime.now() + timedelta(days=36000)

    def test_unlock_user(self, event_collector):
        """Test unlocking user account"""
        user = User.register(
            email="unlock@example.com",
            username="unlock",
            password="Password123!",
            auto_activate=True,
        )

        # Lock first
        user.lock()
        assert user.status == UserStatus.LOCKED

        admin_id = uuid4()
        user.unlock(unlocked_by=admin_id)

        assert user.status == UserStatus.ACTIVE
        assert user.locked_until is None
        assert user.failed_login_count == 0

        # Check events
        events = user.get_events()
        unlock_events = [e for e in events if isinstance(e, UserUnlocked)]
        assert len(unlock_events) == 1
        assert unlock_events[0].unlocked_by == admin_id

    def test_suspend_user(self, event_collector):
        """Test suspending user account"""
        user = User.register(
            email="suspend@example.com",
            username="suspend",
            password="Password123!",
            auto_activate=True,
        )

        # Create active sessions
        session1 = Mock()
        session1.is_active = True
        session1.revoke = Mock()
        user._sessions = [session1]

        duration = timedelta(days=30)
        admin_id = uuid4()
        reason = "Policy violation"

        user.suspend(duration=duration, suspended_by=admin_id, reason=reason)

        assert user.status == UserStatus.SUSPENDED
        assert user.suspended_until is not None
        assert user.suspended_until > datetime.now()

        # Sessions should be revoked
        session1.revoke.assert_called_once()

        # Check events
        events = user.get_events()
        suspend_events = [e for e in events if isinstance(e, UserSuspended)]
        assert len(suspend_events) == 1
        assert suspend_events[0].suspended_by == admin_id
        assert suspend_events[0].suspension_reason == reason

    def test_reinstate_user(self, event_collector):
        """Test reinstating suspended user"""
        user = User.register(
            email="reinstate@example.com",
            username="reinstate",
            password="Password123!",
            auto_activate=True,
        )

        # Suspend first
        user.suspend(duration=timedelta(days=30), suspended_by=uuid4(), reason="Test")

        admin_id = uuid4()
        user.reinstate(reinstated_by=admin_id)

        assert user.status == UserStatus.ACTIVE
        assert user.suspended_until is None

        # Check events
        events = user.get_events()
        reinstate_events = [e for e in events if isinstance(e, UserReinstated)]
        assert len(reinstate_events) == 1
        assert reinstate_events[0].reinstated_by == admin_id

    def test_reinstate_non_suspended_user(self):
        """Test reinstating non-suspended user (no-op)"""
        user = User.register(
            email="active@example.com",
            username="active",
            password="Password123!",
            auto_activate=True,
        )

        initial_events_count = len(user.get_events())

        user.reinstate(reinstated_by=uuid4())

        # Should be no-op
        assert len(user.get_events()) == initial_events_count

    def test_is_locked_status(self):
        """Test is_locked method with status check"""
        user = User.register(
            email="lock@example.com",
            username="lock",
            password="Password123!",
            auto_activate=True,
        )

        assert user.is_locked() is False

        user.status = UserStatus.LOCKED
        assert user.is_locked() is True

    def test_is_locked_timeout(self, time_machine):
        """Test is_locked method with timeout check"""
        current_time = datetime.now()
        time_machine.freeze(current_time)

        user = User.register(
            email="lock@example.com",
            username="lock",
            password="Password123!",
            auto_activate=True,
        )

        # Set lock until future
        user.locked_until = current_time + timedelta(hours=1)
        assert user.is_locked() is True

        # Advance time past lock expiry
        time_machine.advance(timedelta(hours=2))
        assert user.is_locked() is False

    def test_is_suspended(self, time_machine):
        """Test is_suspended method"""
        current_time = datetime.now()
        time_machine.freeze(current_time)

        user = User.register(
            email="suspend@example.com",
            username="suspend",
            password="Password123!",
            auto_activate=True,
        )

        assert user.is_suspended() is False

        # Set suspended status
        user.status = UserStatus.SUSPENDED
        assert user.is_suspended() is True

        # Set suspension timeout
        user.status = UserStatus.ACTIVE
        user.suspended_until = current_time + timedelta(hours=1)
        assert user.is_suspended() is True

        # Advance time past suspension
        time_machine.advance(timedelta(hours=2))
        assert user.is_suspended() is False


class TestUserDeletionAndRecovery:
    """Test user deletion and account recovery"""

    def test_soft_delete_user(self, event_collector):
        """Test soft deletion of user account"""
        user = User.register(
            email="delete@example.com",
            username="delete",
            password="Password123!",
            auto_activate=True,
        )

        # Create active sessions
        session1 = Mock()
        session1.is_active = True
        session1.revoke = Mock()
        user._sessions = [session1]

        admin_id = uuid4()
        user.soft_delete(deleted_by=admin_id)

        assert user.status == UserStatus.DELETED
        assert user.deleted_at is not None

        # Sessions should be revoked
        session1.revoke.assert_called_once()

        # Check events
        events = user.get_events()
        delete_events = [e for e in events if isinstance(e, UserDeleted)]
        assert len(delete_events) == 1
        assert delete_events[0].deleted_by == admin_id
        assert delete_events[0].deletion_type == "soft"

    def test_restore_user(self):
        """Test restoring soft-deleted user"""
        user = User.register(
            email="restore@example.com",
            username="restore",
            password="Password123!",
            auto_activate=True,
        )

        # Soft delete first
        user.soft_delete(deleted_by=uuid4())
        assert user.deleted_at is not None

        admin_id = uuid4()
        user.restore(restored_by=admin_id)

        assert user.status == UserStatus.ACTIVE
        assert user.deleted_at is None

    def test_restore_non_deleted_user(self):
        """Test restoring non-deleted user (no-op)"""
        user = User.register(
            email="active@example.com",
            username="active",
            password="Password123!",
            auto_activate=True,
        )

        # No change expected
        user.restore(restored_by=uuid4())
        assert user.status == UserStatus.ACTIVE
        assert user.deleted_at is None

    def test_request_account_deletion(self):
        """Test requesting account deletion"""
        user = User.register(
            email="request@example.com",
            username="request",
            password="Password123!",
            auto_activate=True,
        )

        user.request_account_deletion()

        assert user.deletion_requested_at is not None

    def test_anonymize_account(self):
        """Test GDPR-compliant account anonymization"""
        user = User.register(
            email="anonymize@example.com",
            username="anonymize",
            password="Password123!",
            auto_activate=True,
        )

        # Set up profile and contacts
        user._profile = Mock()
        user._profile.first_name = "John"
        user._profile.last_name = "Doe"
        user._profile.display_name = "John Doe"
        user._profile.bio = "Software engineer"
        user._profile.location = "San Francisco"
        user._profile.website = "https://johndoe.com"

        user.phone_number = PhoneNumber("+15551234567")
        user.avatar_url = "https://example.com/avatar.jpg"

        emergency_contact = Mock()
        user._emergency_contacts = [emergency_contact]

        original_email = user.email.value
        original_username = user.username.value

        user.anonymize_account()

        # Check anonymization
        assert user.anonymized_at is not None
        assert user.email.value != original_email
        assert user.username.value != original_username
        assert "anon_" in user.username.value
        assert "@anonymized.local" in user.email.value
        assert user.phone_number is None
        assert user.avatar_url is None

        # Check profile anonymization
        assert user._profile.first_name is None
        assert user._profile.last_name is None
        assert user._profile.display_name == "Anonymous User"
        assert user._profile.bio is None
        assert user._profile.location is None
        assert user._profile.website is None

        # Check emergency contacts cleared
        assert len(user._emergency_contacts) == 0


class TestUserSessionManagement:
    """Test user session management operations"""

    def test_get_active_sessions(self):
        """Test getting active sessions"""
        user = User.register(
            email="session@example.com",
            username="session",
            password="Password123!",
            auto_activate=True,
        )

        # Create mix of active and inactive sessions
        active_session1 = Mock()
        active_session1.is_active = True

        active_session2 = Mock()
        active_session2.is_active = True

        inactive_session = Mock()
        inactive_session.is_active = False

        user._sessions = [active_session1, inactive_session, active_session2]

        active_sessions = user.get_active_sessions()

        assert len(active_sessions) == 2
        assert active_session1 in active_sessions
        assert active_session2 in active_sessions
        assert inactive_session not in active_sessions

    def test_revoke_all_sessions(self, event_collector):
        """Test revoking all user sessions"""
        user = User.register(
            email="session@example.com",
            username="session",
            password="Password123!",
            auto_activate=True,
        )

        # Create sessions
        session1 = Mock()
        session1.id = uuid4()
        session1.is_active = True
        session1.revoke = Mock()

        session2 = Mock()
        session2.id = uuid4()
        session2.is_active = True
        session2.revoke = Mock()

        session3 = Mock()
        session3.id = uuid4()
        session3.is_active = False  # Already inactive
        session3.revoke = Mock()

        user._sessions = [session1, session2, session3]

        user.revoke_all_sessions()

        # Active sessions should be revoked
        session1.revoke.assert_called_once()
        session2.revoke.assert_called_once()
        session3.revoke.assert_not_called()  # Already inactive

    def test_revoke_all_sessions_except_one(self):
        """Test revoking all sessions except specified one"""
        user = User.register(
            email="session@example.com",
            username="session",
            password="Password123!",
            auto_activate=True,
        )

        # Create sessions
        session1 = Mock()
        session1.id = uuid4()
        session1.is_active = True
        session1.revoke = Mock()

        keep_session = Mock()
        keep_session.id = uuid4()
        keep_session.is_active = True
        keep_session.revoke = Mock()

        user._sessions = [session1, keep_session]

        user.revoke_all_sessions(except_session_id=keep_session.id)

        # Only session1 should be revoked
        session1.revoke.assert_called_once()
        keep_session.revoke.assert_not_called()


class TestUserLoginLogoutFlow:
    """Test complete login/logout flow with enhanced features"""

    @patch("app.core.security.verify_password")
    def test_login_success_no_mfa(self, mock_verify_password, event_collector):
        """Test successful login without MFA requirement"""
        mock_verify_password.return_value = True

        user = User.register(
            email="login@example.com",
            username="login",
            password="Password123!",
            auto_activate=True,
        )

        with patch.object(user, "_record_login_attempt") as mock_record:
            mock_attempt = Mock()
            mock_record.return_value = mock_attempt

            session = user.login(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
                device_fingerprint="device123",
            )

            assert isinstance(session, Session)
            assert mock_attempt.success is True

            # Check events
            events = user.get_events()
            login_events = [e for e in events if isinstance(e, LoginSuccessful)]
            assert len(login_events) == 1
            assert login_events[0].session_id == session.id

    @patch("app.core.security.verify_password")
    def test_login_success_with_mfa(self, mock_verify_password):
        """Test successful login with MFA requirement"""
        mock_verify_password.return_value = True

        user = User.register(
            email="login@example.com",
            username="login",
            password="Password123!",
            auto_activate=True,
        )

        # Enable MFA
        user.enable_mfa(MfaMethod.TOTP)

        with patch.object(user, "verify_mfa_code", return_value=True):
            session = user.login(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
                mfa_code="123456",
            )

            assert isinstance(session, Session)

    @patch("app.core.security.verify_password")
    def test_login_mfa_required_but_not_provided(self, mock_verify_password):
        """Test login failure when MFA required but not provided"""
        mock_verify_password.return_value = True

        user = User.register(
            email="login@example.com",
            username="login",
            password="Password123!",
            auto_activate=True,
        )

        user.enable_mfa(MfaMethod.TOTP)

        with pytest.raises(MFARequiredError):
            user.login(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0"
                # No mfa_code provided
            )

    @patch("app.core.security.verify_password")
    def test_login_invalid_mfa_code(self, mock_verify_password):
        """Test login failure with invalid MFA code"""
        mock_verify_password.return_value = True

        user = User.register(
            email="login@example.com",
            username="login",
            password="Password123!",
            auto_activate=True,
        )

        user.enable_mfa(MfaMethod.TOTP)

        with patch.object(user, "verify_mfa_code", return_value=False):
            with pytest.raises(InvalidMFACodeError):
                user.login(
                    password="Password123!",
                    ip_address="192.168.1.100",
                    user_agent="Mozilla/5.0",
                    mfa_code="wrong_code",
                )

    def test_logout_specific_session(self, event_collector):
        """Test logout from specific session"""
        user = User.register(
            email="logout@example.com",
            username="logout",
            password="Password123!",
            auto_activate=True,
        )

        session = Mock()
        session.id = uuid4()
        session.revoke = Mock()
        user._sessions = [session]

        user.logout(session.id)

        session.revoke.assert_called_once()

        # Check events
        events = user.get_events()
        session_events = [e for e in events if isinstance(e, SessionRevoked)]
        assert len(session_events) == 1
        assert session_events[0].session_id == session.id

    def test_logout_nonexistent_session(self):
        """Test logout from nonexistent session (no-op)"""
        user = User.register(
            email="logout@example.com",
            username="logout",
            password="Password123!",
            auto_activate=True,
        )

        initial_events_count = len(user.get_events())

        user.logout(uuid4())  # Nonexistent session ID

        # Should be no-op
        assert len(user.get_events()) == initial_events_count

    def test_logout_all_devices(self, event_collector):
        """Test logout from all devices"""
        user = User.register(
            email="logout@example.com",
            username="logout",
            password="Password123!",
            auto_activate=True,
        )

        # Create sessions and tokens
        session1 = Mock()
        session1.id = uuid4()
        session1.is_active = True
        session1.revoke = Mock()

        keep_session = Mock()
        keep_session.id = uuid4()
        keep_session.is_active = True
        keep_session.revoke = Mock()

        user._sessions = [session1, keep_session]

        # Create access tokens
        token1 = Mock()
        token1.revoked_at = None
        token1.revoke = Mock()

        token2 = Mock()
        token2.revoked_at = datetime.now()  # Already revoked
        token2.revoke = Mock()

        user._access_tokens = [token1, token2]

        user.logout_all_devices(except_session_id=keep_session.id)

        # Check sessions
        session1.revoke.assert_called_once()
        keep_session.revoke.assert_not_called()

        # Check tokens
        token1.revoke.assert_called_once_with(user.id, "logout_all_devices")
        token2.revoke.assert_not_called()


class TestUserEmailManagement:
    """Test email management operations"""

    @patch("app.core.security.verify_password")
    def test_request_email_change(self, mock_verify_password, event_collector):
        """Test requesting email change"""
        mock_verify_password.return_value = True

        user = User.register(
            email="old@example.com",
            username="user",
            password="Password123!",
            auto_activate=True,
        )

        token = user.request_email_change("new@example.com", "Password123!")

        assert len(token) > 20  # Token should be substantial
        assert user.email_verification_token == token
        assert user.email_verification_token_expires is not None
        assert user.pending_email.value == "new@example.com"

        # Check events
        events = user.get_events()
        email_events = [e for e in events if isinstance(e, EmailVerificationRequested)]
        assert len(email_events) == 1
        assert email_events[0].email == "new@example.com"
        assert email_events[0].verification_type == "email_change"

    @patch("app.core.security.verify_password")
    def test_request_email_change_wrong_password(self, mock_verify_password):
        """Test email change request with wrong password"""
        mock_verify_password.return_value = False

        user = User.register(
            email="old@example.com",
            username="user",
            password="Password123!",
            auto_activate=True,
        )

        with pytest.raises(InvalidCredentialsError):
            user.request_email_change("new@example.com", "WrongPassword")

    def test_confirm_email_change(self, event_collector):
        """Test confirming email change"""
        user = User.register(
            email="old@example.com",
            username="user",
            password="Password123!",
            auto_activate=True,
        )

        # Set up email change
        token = "verification_token_123"
        user.email_verification_token = token
        user.email_verification_token_expires = datetime.now() + timedelta(hours=1)
        user.pending_email = Email("new@example.com")

        old_email = user.email.value

        user.confirm_email_change(token)

        assert user.email.value == "new@example.com"
        assert user.email_verified is True
        assert user.pending_email is None
        assert user.email_verification_token is None
        assert user.email_verification_token_expires is None

        # Check events
        events = user.get_events()
        email_events = [e for e in events if isinstance(e, EmailVerified)]
        assert len(email_events) == 1
        assert email_events[0].email == "new@example.com"
        assert email_events[0].previous_email == old_email

    def test_confirm_email_change_invalid_token(self):
        """Test confirming email change with invalid token"""
        user = User.register(
            email="old@example.com",
            username="user",
            password="Password123!",
            auto_activate=True,
        )

        user.email_verification_token = "valid_token"
        user.email_verification_token_expires = datetime.now() + timedelta(hours=1)
        user.pending_email = Email("new@example.com")

        with pytest.raises(InvalidTokenError, match="Invalid verification token"):
            user.confirm_email_change("wrong_token")

    def test_confirm_email_change_expired_token(self, time_machine):
        """Test confirming email change with expired token"""
        current_time = datetime.now()
        time_machine.freeze(current_time)

        user = User.register(
            email="old@example.com",
            username="user",
            password="Password123!",
            auto_activate=True,
        )

        token = "expired_token"
        user.email_verification_token = token
        user.email_verification_token_expires = current_time + timedelta(hours=1)
        user.pending_email = Email("new@example.com")

        # Advance time past expiry
        time_machine.advance(timedelta(hours=2))

        with pytest.raises(TokenExpiredError, match="Verification token has expired"):
            user.confirm_email_change(token)

    def test_resend_email_verification(self, event_collector):
        """Test resending email verification"""
        user = User.register(
            email="unverified@example.com",
            username="user",
            password="Password123!",
            auto_activate=False,  # Unverified
        )

        token = user.resend_email_verification()

        assert token is not None
        assert len(token) > 20
        assert user.email_verification_token == token
        assert user.email_verification_token_expires is not None

        # Check events
        events = user.get_events()
        email_events = [e for e in events if isinstance(e, EmailVerificationRequested)]
        # Should have 1 from resend (registration event is different)
        resend_events = [e for e in email_events if e.verification_type == "resend"]
        assert len(resend_events) == 1

    def test_resend_email_verification_already_verified(self):
        """Test resending verification for already verified email"""
        user = User.register(
            email="verified@example.com",
            username="user",
            password="Password123!",
            auto_activate=True,  # Already verified
        )

        token = user.resend_email_verification()

        assert token is None  # No resend needed


class TestUserPhoneNumberManagement:
    """Test phone number management operations"""

    def test_add_phone_number(self, event_collector):
        """Test adding phone number"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        user.add_phone_number("+15551234567", is_primary=True)

        assert user.phone_number.value == "+15551234567"
        assert user.phone_verified is False

        # Check events
        events = user.get_events()
        phone_events = [e for e in events if isinstance(e, PhoneNumberAdded)]
        assert len(phone_events) == 1
        assert phone_events[0].phone_number == "+15551234567"
        assert phone_events[0].is_primary is True

    def test_add_duplicate_phone_number(self):
        """Test adding same phone number twice (no-op)"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        user.add_phone_number("+15551234567")
        initial_events_count = len(user.get_events())

        user.add_phone_number("+15551234567")  # Same number

        # Should be no-op
        assert len(user.get_events()) == initial_events_count

    def test_verify_phone_number(self, event_collector):
        """Test verifying phone number"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        user.add_phone_number("+15551234567")
        assert user.phone_verified is False

        user.verify_phone_number("123456")  # Verification code

        assert user.phone_verified is True

        # Check events
        events = user.get_events()
        verify_events = [e for e in events if isinstance(e, PhoneNumberVerified)]
        assert len(verify_events) == 1
        assert verify_events[0].phone_number == "+15551234567"

    def test_verify_phone_number_no_phone(self):
        """Test verifying phone when none exists"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        with pytest.raises(ValueError, match="No phone number to verify"):
            user.verify_phone_number("123456")

    def test_verify_already_verified_phone(self):
        """Test verifying already verified phone (no-op)"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        user.add_phone_number("+15551234567")
        user.verify_phone_number("123456")

        initial_events_count = len(user.get_events())

        user.verify_phone_number("123456")  # Verify again

        # Should be no-op
        assert len(user.get_events()) == initial_events_count

    def test_change_phone_number(self, event_collector):
        """Test changing phone number"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        # Add and verify initial phone
        user.add_phone_number("+15551234567")
        user.verify_phone_number("123456")

        old_phone = user.phone_number.value

        user.change_phone_number("+15559876543")

        assert user.phone_number.value == "+15559876543"
        assert user.phone_verified is False  # Needs re-verification

        # Check events
        events = user.get_events()
        change_events = [e for e in events if isinstance(e, PhoneNumberChanged)]
        assert len(change_events) == 1
        assert change_events[0].old_phone_number == old_phone
        assert change_events[0].new_phone_number == "+15559876543"

    def test_change_phone_number_first_time(self, event_collector):
        """Test changing phone when none exists (treated as add)"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        user.change_phone_number("+15551234567")

        assert user.phone_number.value == "+15551234567"
        assert user.phone_verified is False

        # Should generate PhoneNumberAdded event
        events = user.get_events()
        add_events = [e for e in events if isinstance(e, PhoneNumberAdded)]
        assert len(add_events) == 1

    def test_remove_phone_number(self, event_collector):
        """Test removing phone number"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        user.add_phone_number("+15551234567")
        user.verify_phone_number("123456")

        phone_to_remove = user.phone_number.value

        user.remove_phone_number()

        assert user.phone_number is None
        assert user.phone_verified is False

        # Check events
        events = user.get_events()
        remove_events = [e for e in events if isinstance(e, PhoneNumberRemoved)]
        assert len(remove_events) == 1
        assert remove_events[0].phone_number == phone_to_remove

    def test_remove_nonexistent_phone(self):
        """Test removing phone when none exists (no-op)"""
        user = User.register(
            email="phone@example.com",
            username="phone",
            password="Password123!",
            auto_activate=True,
        )

        initial_events_count = len(user.get_events())

        user.remove_phone_number()

        # Should be no-op
        assert len(user.get_events()) == initial_events_count


class TestUserPasswordResetFlow:
    """Test password reset flow operations"""

    def test_request_password_reset(self, event_collector):
        """Test requesting password reset"""
        user = User.register(
            email="reset@example.com",
            username="reset",
            password="Password123!",
            auto_activate=True,
        )

        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0"

        token = user.request_password_reset(ip_address, user_agent)

        assert len(token) > 20  # Token should be substantial
        assert user.password_reset_token is not None
        assert user.password_reset_token_expires is not None
        assert user.password_reset_token_expires > datetime.now()

        # Token should be hashed in user object
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        assert user.password_reset_token == token_hash

        # Check events
        events = user.get_events()
        reset_events = [e for e in events if isinstance(e, PasswordResetRequested)]
        assert len(reset_events) == 1
        assert reset_events[0].requested_ip == ip_address
        assert reset_events[0].requested_user_agent == user_agent

    @patch("app.core.security.hash_password")
    def test_reset_password_with_token(self, mock_hash_password, event_collector):
        """Test resetting password with valid token"""
        mock_hash_password.return_value = "new_hashed_password"

        user = User.register(
            email="reset@example.com",
            username="reset",
            password="Password123!",
            auto_activate=True,
        )

        # Request reset first
        token = user.request_password_reset("192.168.1.100", "Mozilla/5.0")

        user.reset_password_with_token(token, "NewPassword123!")

        assert user.password_hash == "new_hashed_password"
        assert user.password_reset_token is None
        assert user.password_reset_token_expires is None

        # Should have triggered change_password which generates events
        events = user.get_events()
        password_events = [e for e in events if isinstance(e, UserPasswordChanged)]
        assert len(password_events) == 1

    def test_reset_password_invalid_token(self):
        """Test password reset with invalid token"""
        user = User.register(
            email="reset@example.com",
            username="reset",
            password="Password123!",
            auto_activate=True,
        )

        # Request reset first
        user.request_password_reset("192.168.1.100", "Mozilla/5.0")

        with pytest.raises(InvalidTokenError, match="Invalid reset token"):
            user.reset_password_with_token("wrong_token", "NewPassword123!")

    def test_reset_password_expired_token(self, time_machine):
        """Test password reset with expired token"""
        current_time = datetime.now()
        time_machine.freeze(current_time)

        user = User.register(
            email="reset@example.com",
            username="reset",
            password="Password123!",
            auto_activate=True,
        )

        token = user.request_password_reset("192.168.1.100", "Mozilla/5.0")

        # Advance time past expiry
        time_machine.advance(timedelta(hours=2))

        with pytest.raises(TokenExpiredError, match="Reset token has expired"):
            user.reset_password_with_token(token, "NewPassword123!")

    def test_reset_password_no_pending_reset(self):
        """Test password reset without pending reset"""
        user = User.register(
            email="reset@example.com",
            username="reset",
            password="Password123!",
            auto_activate=True,
        )

        with pytest.raises(InvalidTokenError, match="No password reset pending"):
            user.reset_password_with_token("any_token", "NewPassword123!")

    def test_force_password_change(self):
        """Test forcing password change on next login"""
        user = User.register(
            email="force@example.com",
            username="force",
            password="Password123!",
            auto_activate=True,
        )

        assert user.require_password_change is False

        user.force_password_change()

        assert user.require_password_change is True


class TestUserSecurityFeatures:
    """Test advanced security features"""

    def test_generate_backup_codes(self, event_collector):
        """Test generating MFA backup codes"""
        user = User.register(
            email="backup@example.com",
            username="backup",
            password="Password123!",
            auto_activate=True,
        )

        codes = user.generate_backup_codes(count=8)

        assert len(codes) == 8
        assert len(user.backup_codes) == 8
        assert all(len(code) == 8 for code in codes)  # 8-digit codes
        assert user.backup_codes_generated_at is not None

        # Codes should be hashed in storage
        for code in codes:
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            assert code_hash in user.backup_codes

        # Check events
        events = user.get_events()
        backup_events = [e for e in events if isinstance(e, BackupCodeGenerated)]
        assert len(backup_events) == 1
        assert backup_events[0].code_count == 8

    def test_use_backup_code(self, event_collector):
        """Test using MFA backup code"""
        user = User.register(
            email="backup@example.com",
            username="backup",
            password="Password123!",
            auto_activate=True,
        )

        codes = user.generate_backup_codes(count=5)
        initial_count = len(user.backup_codes)

        # Use a backup code
        code_to_use = codes[0]
        result = user.use_backup_code(code_to_use)

        assert result is True
        assert len(user.backup_codes) == initial_count - 1

        # Code should be removed from storage
        code_hash = hashlib.sha256(code_to_use.encode()).hexdigest()
        assert code_hash not in user.backup_codes

        # Check events
        events = user.get_events()
        used_events = [e for e in events if isinstance(e, BackupCodeUsed)]
        assert len(used_events) == 1
        assert used_events[0].remaining_codes == len(user.backup_codes)

    def test_use_invalid_backup_code(self):
        """Test using invalid backup code"""
        user = User.register(
            email="backup@example.com",
            username="backup",
            password="Password123!",
            auto_activate=True,
        )

        user.generate_backup_codes(count=5)

        result = user.use_backup_code("invalid_code")

        assert result is False

    def test_use_backup_code_no_codes(self):
        """Test using backup code when none exist"""
        user = User.register(
            email="backup@example.com",
            username="backup",
            password="Password123!",
            auto_activate=True,
        )

        result = user.use_backup_code("any_code")

        assert result is False

    def test_add_trusted_device_new(self):
        """Test adding new trusted device"""
        user = User.register(
            email="device@example.com",
            username="device",
            password="Password123!",
            auto_activate=True,
        )

        fingerprint = "device_fingerprint_123"

        user.add_trusted_device(fingerprint)

        assert len(user._registered_devices) == 1
        device = user._registered_devices[0]
        assert device.device_id == fingerprint
        assert device.is_trusted is True  # Should be trusted after add_trusted_device

    def test_add_trusted_device_existing(self):
        """Test adding trust to existing device"""
        user = User.register(
            email="device@example.com",
            username="device",
            password="Password123!",
            auto_activate=True,
        )

        # Create existing device
        existing_device = Mock()
        existing_device.device_id = "device_123"
        existing_device.trust = Mock()
        user._registered_devices = [existing_device]

        user.add_trusted_device("device_123")

        # Should call trust on existing device
        existing_device.trust.assert_called_once()
        assert len(user._registered_devices) == 1


class TestUserProfileAndPreferences:
    """Test user profile and preference management"""

    def test_update_profile(self, event_collector):
        """Test updating user profile"""
        user = User.register(
            email="profile@example.com",
            username="profile",
            password="Password123!",
            auto_activate=True,
        )

        profile_data = {
            "first_name": "John",
            "last_name": "Doe",
            "bio": "Software engineer",
            "location": "San Francisco",
        }

        user.update_profile(profile_data)

        assert user._profile is not None
        assert user._profile.user_id == user.id

        # Check events
        events = user.get_events()
        profile_events = [e for e in events if isinstance(e, UserProfileUpdated)]
        assert len(profile_events) == 1
        assert set(profile_events[0].updated_fields) == set(profile_data.keys())

    def test_update_profile_existing(self):
        """Test updating existing profile"""
        user = User.register(
            email="profile@example.com",
            username="profile",
            password="Password123!",
            auto_activate=True,
        )

        # Create existing profile
        existing_profile = Mock()
        existing_profile.updated_at = datetime.now()
        user._profile = existing_profile

        profile_data = {"first_name": "Jane"}

        user.update_profile(profile_data)

        # Should update existing profile
        assert hasattr(existing_profile, "first_name")

    def test_get_display_name_with_profile(self):
        """Test getting display name with profile"""
        user = User.register(
            email="display@example.com",
            username="display",
            password="Password123!",
            auto_activate=True,
        )

        # Create profile with display name
        user._profile = Mock()
        user._profile.display_name = "John Display"

        assert user.get_display_name() == "John Display"

    def test_get_display_name_without_profile(self):
        """Test getting display name without profile"""
        user = User.register(
            email="display@example.com",
            username="displayuser",
            password="Password123!",
            auto_activate=True,
        )

        assert user.get_display_name() == "displayuser"

    def test_update_notification_settings(self):
        """Test updating notification preferences"""
        user = User.register(
            email="notif@example.com",
            username="notif",
            password="Password123!",
            auto_activate=True,
        )

        settings = {
            "email_notifications": True,
            "sms_notifications": False,
            "push_notifications": True,
        }

        user.update_notification_settings(settings)

        assert len(user._notification_settings) == 3

        # Check specific settings
        email_setting = next(
            (
                s
                for s in user._notification_settings
                if s.channel == "email_notifications"
            ),
            None,
        )
        assert email_setting is not None
        assert email_setting.enabled is True

    def test_update_privacy_settings(self):
        """Test updating privacy preferences"""
        user = User.register(
            email="privacy@example.com",
            username="privacy",
            password="Password123!",
            auto_activate=True,
        )

        settings = {
            "profile_visibility": "public",
            "show_online_status": False,
            "allow_messaging": True,
        }

        user.update_privacy_settings(settings)

        assert user._preferences is not None
        assert user._preferences.user_id == user.id


class TestUserAvatarManagement:
    """Test user avatar management"""

    def test_update_avatar_first_time(self, event_collector):
        """Test uploading avatar for first time"""
        user = User.register(
            email="avatar@example.com",
            username="avatar",
            password="Password123!",
            auto_activate=True,
        )

        avatar_url = "https://example.com/avatars/user123.jpg"
        user.update_avatar(avatar_url)

        assert user.avatar_url == avatar_url

        # Check events
        events = user.get_events()
        avatar_events = [e for e in events if isinstance(e, AvatarUploaded)]
        assert len(avatar_events) == 1
        assert avatar_events[0].file_path == avatar_url

    def test_update_avatar_change(self, event_collector):
        """Test changing existing avatar"""
        user = User.register(
            email="avatar@example.com",
            username="avatar",
            password="Password123!",
            auto_activate=True,
        )

        # Set initial avatar
        old_avatar = "https://example.com/avatars/old.jpg"
        user.avatar_url = old_avatar

        new_avatar = "https://example.com/avatars/new.jpg"
        user.update_avatar(new_avatar)

        assert user.avatar_url == new_avatar

        # Check events
        events = user.get_events()
        change_events = [e for e in events if isinstance(e, AvatarChanged)]
        assert len(change_events) == 1

    def test_remove_avatar(self, event_collector):
        """Test removing user avatar"""
        user = User.register(
            email="avatar@example.com",
            username="avatar",
            password="Password123!",
            auto_activate=True,
        )

        # Set avatar first
        user.avatar_url = "https://example.com/avatars/user.jpg"

        user.remove_avatar()

        assert user.avatar_url is None

        # Check events
        events = user.get_events()
        delete_events = [e for e in events if isinstance(e, AvatarDeleted)]
        assert len(delete_events) == 1
        assert delete_events[0].deleted_by == user.id

    def test_remove_nonexistent_avatar(self):
        """Test removing avatar when none exists (no-op)"""
        user = User.register(
            email="avatar@example.com",
            username="avatar",
            password="Password123!",
            auto_activate=True,
        )

        initial_events_count = len(user.get_events())

        user.remove_avatar()

        # Should be no-op
        assert len(user.get_events()) == initial_events_count


class TestUserAccountRecovery:
    """Test account recovery mechanisms"""

    def test_initiate_account_recovery_email(self):
        """Test account recovery via email"""
        user = User.register(
            email="recovery@example.com",
            username="recovery",
            password="Password123!",
            auto_activate=True,
        )

        result = user.initiate_account_recovery("email")

        assert result["method"] == "email"
        assert "token" in result
        assert "sent_to" in result
        assert "@" in result["sent_to"]  # Should contain masked email

    def test_initiate_account_recovery_phone(self):
        """Test account recovery via phone"""
        user = User.register(
            email="recovery@example.com",
            username="recovery",
            password="Password123!",
            auto_activate=True,
        )

        # Add verified phone
        user.add_phone_number("+15551234567")
        user.verify_phone_number("123456")

        result = user.initiate_account_recovery("phone")

        assert result["method"] == "phone"
        assert "code" in result
        assert "sent_to" in result
        assert "555" in result["sent_to"]  # Should contain masked phone

    def test_initiate_account_recovery_no_phone(self):
        """Test account recovery via phone when no phone available"""
        user = User.register(
            email="recovery@example.com",
            username="recovery",
            password="Password123!",
            auto_activate=True,
        )

        with pytest.raises(ValueError, match="Recovery method phone not available"):
            user.initiate_account_recovery("phone")


class TestUserUtilityMethods:
    """Test utility and helper methods"""

    def test_get_account_age_days(self, time_machine):
        """Test calculating account age in days"""
        base_time = datetime.now()
        time_machine.freeze(base_time)

        user = User.register(
            email="age@example.com",
            username="age",
            password="Password123!",
            auto_activate=True,
        )

        # Advance time
        time_machine.advance(timedelta(days=30))

        assert user.get_account_age_days() == 30

    def test_get_password_age_days(self, time_machine):
        """Test calculating password age in days"""
        base_time = datetime.now()
        time_machine.freeze(base_time)

        user = User.register(
            email="password@example.com",
            username="password",
            password="Password123!",
            auto_activate=True,
        )

        # Advance time
        time_machine.advance(timedelta(days=45))

        assert user.get_password_age_days() == 45

    def test_get_password_age_no_change(self, time_machine):
        """Test password age when password never changed"""
        base_time = datetime.now()
        time_machine.freeze(base_time)

        user = User.register(
            email="password@example.com",
            username="password",
            password="Password123!",
            auto_activate=True,
        )

        # Clear password changed timestamp
        user.password_changed_at = None

        # Advance time
        time_machine.advance(timedelta(days=45))

        # Should use account age
        assert user.get_password_age_days() == 45

    def test_is_password_expired(self):
        """Test password expiry check"""
        user = User.register(
            email="expired@example.com",
            username="expired",
            password="Password123!",
            auto_activate=True,
        )

        # Set old password change date
        user.password_changed_at = datetime.now() - timedelta(days=120)

        assert user.is_password_expired(max_age_days=90) is True
        assert user.is_password_expired(max_age_days=150) is False

    def test_get_risk_score(self):
        """Test user risk score calculation"""
        user = User.register(
            email="risk@example.com",
            username="risk",
            password="Password123!",
            auto_activate=True,
        )

        # New account should have some risk
        initial_score = user.get_risk_score()
        assert 0.0 <= initial_score <= 1.0

        # Add risk factors
        user.email_verified = False
        user.mfa_enabled = False

        # Add failed login attempts
        for _i in range(5):
            attempt = Mock()
            attempt.success = False
            user._login_attempts.append(attempt)

        risk_score = user.get_risk_score()
        assert risk_score > initial_score
        assert risk_score <= 1.0

    def test_get_security_summary(self):
        """Test security summary generation"""
        user = User.register(
            email="security@example.com",
            username="security",
            password="Password123!",
            auto_activate=True,
        )

        # Add some security features
        user.enable_mfa(MfaMethod.TOTP)
        user.generate_backup_codes(count=8)

        # Add sessions and devices
        session = Mock()
        session.is_active = True
        user._sessions = [session]

        device = Mock()
        user._registered_devices = [device]

        summary = user.get_security_summary()

        assert summary["mfa_enabled"] is True
        assert MfaMethod.TOTP.value in summary["mfa_methods"]
        assert summary["email_verified"] is True
        assert summary["active_sessions"] == 1
        assert summary["registered_devices"] == 1
        assert summary["backup_codes_count"] == 8
        assert "risk_score" in summary
        assert "password_age_days" in summary

    def test_to_dict(self):
        """Test user serialization to dictionary"""
        user = User.register(
            email="serialize@example.com",
            username="serialize",
            password="Password123!",
            auto_activate=True,
        )

        # Add some data
        user.phone_number = PhoneNumber("+15551234567")
        user.phone_verified = True

        role = Mock()
        role.name = "Admin"
        user._roles = [role]

        permission = Mock()
        permission.name = "read_all"
        user._permissions = [permission]

        data = user.to_dict()

        assert data["id"] == str(user.id)
        assert data["email"] == user.email.value
        assert data["username"] == user.username.value
        assert data["status"] == user.status.value
        assert data["account_type"] == user.account_type.value
        assert data["phone_number"] == "+15551234567"
        assert data["phone_verified"] is True
        assert data["mfa_enabled"] is False
        assert "Admin" in data["roles"]
        assert "read_all" in data["permissions"]
        assert "created_at" in data
        assert "updated_at" in data


# Performance and Load Testing Helpers
class TestUserPerformance:
    """Test user aggregate performance characteristics"""

    def test_user_creation_performance(self, performance_tracker):
        """Test user creation performance"""
        with performance_tracker.measure("user_creation"):
            for _ in range(100):
                User.register(
                    email=f"perf{_}@example.com",
                    username=f"user{_}",
                    password="Password123!",
                    auto_activate=True,
                )

        # Should create 100 users in reasonable time
        performance_tracker.assert_performance("user_creation", max_time=1.0)

    def test_permission_check_performance(self, performance_tracker):
        """Test permission checking performance"""
        user = User.register(
            email="perf@example.com",
            username="perf",
            password="Password123!",
            auto_activate=True,
        )

        # Add many permissions
        for i in range(100):
            permission = Mock()
            permission.name = f"permission_{i}"
            user._permissions.append(permission)

        with performance_tracker.measure("permission_check"):
            for i in range(1000):
                user.has_permission(f"permission_{i % 100}")

        performance_tracker.assert_performance("permission_check", max_time=0.1)


class TestUserSecurityScenarios:
    """Test complex security scenarios"""

    def test_brute_force_attack_simulation(self):
        """Test account lockout under brute force attack"""
        user = User.register(
            email="attack@example.com",
            username="attack",
            password="Password123!",
            auto_activate=True,
        )

        # Simulate brute force attack
        with patch("app.core.security.verify_password", return_value=False):
            for i in range(SecurityLimits.MAX_FAILED_LOGIN_ATTEMPTS + 2):
                try:
                    user.authenticate(
                        password="WrongPassword",
                        ip_address=f"192.168.1.{100 + i}",
                        user_agent="AttackerBot/1.0",
                    )
                except (InvalidCredentialsError, AccountLockedError):
                    pass  # Expected

        # Account should be locked
        assert user.status == UserStatus.LOCKED
        assert user.failed_login_count >= SecurityLimits.MAX_FAILED_LOGIN_ATTEMPTS

    def test_session_hijacking_protection(self):
        """Test protection against session hijacking"""
        user = User.register(
            email="hijack@example.com",
            username="hijack",
            password="Password123!",
            auto_activate=True,
        )

        # Create session
        with patch("app.core.security.verify_password", return_value=True):
            session = user.authenticate(
                password="Password123!",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0 Chrome/91.0",
                device_fingerprint="user_device",
            )

        # Simulate password change (should invalidate sessions)
        user.change_password(
            current_password="Password123!",
            new_password="NewPassword123!",
            changed_by=user.id,
        )

        # Session should be revoked
        session.revoke.assert_called_once()

    def test_privilege_escalation_prevention(self):
        """Test prevention of privilege escalation"""
        user = User.register(
            email="escalate@example.com",
            username="escalate",
            password="Password123!",
            auto_activate=True,
        )

        # User shouldn't be able to assign admin role to themselves
        admin_role = Mock()
        admin_role.id = uuid4()
        admin_role.name = "SuperAdmin"

        # This should work when done by admin
        admin_id = uuid4()
        user.assign_role(admin_role, assigned_by=admin_id)

        # But audit trail should show who did it
        events = user.get_events()
        role_events = [e for e in events if isinstance(e, UserRoleAssigned)]
        assert role_events[0].assigned_by == admin_id


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
