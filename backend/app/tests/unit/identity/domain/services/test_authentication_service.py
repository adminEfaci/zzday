"""
Comprehensive unit tests for AuthenticationService domain service.

Tests cover:
- Password validation
- Login attempt tracking
- Account locking
- Token generation
- Security rules enforcement
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest

from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.errors import (
    AccountLockedError,
    AccountNotActiveError,
    AuthenticationError,
    InvalidCredentialsError,
)
from app.modules.identity.domain.services.authentication_service import (
    AuthenticationService,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.ip_address import IpAddress
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.user_agent import UserAgent
from app.modules.identity.domain.value_objects.username import Username


class TestAuthenticationService:
    """Test suite for AuthenticationService domain service."""

    @pytest.fixture
    def mock_password_service(self):
        """Create mock password service."""
        service = Mock()
        service.validate_password = Mock(return_value=True)
        service.verify_password = Mock(return_value=True)
        service.hash_password = Mock(return_value=PasswordHash("hashed"))
        return service

    @pytest.fixture
    def mock_token_service(self):
        """Create mock token service."""
        service = Mock()
        service.generate_access_token = Mock(return_value="access_token")
        service.generate_refresh_token = Mock(return_value="refresh_token")
        service.validate_token = Mock(return_value={"user_id": "123", "exp": 1234567890})
        return service

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        repo = AsyncMock()
        return repo

    @pytest.fixture
    def auth_service(self, mock_password_service, mock_token_service, mock_user_repository):
        """Create authentication service with mocks."""
        return AuthenticationService(
            password_service=mock_password_service,
            token_service=mock_token_service,
            user_repository=mock_user_repository,
        )

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user = User.create(
            email=Email("test@example.com"),
            username=Username("testuser"),
            password_hash=PasswordHash.from_password("TestPass123!"),
        )
        user.activate()
        user.pull_domain_events()  # Clear events
        return user

    async def test_authenticate_with_valid_credentials(self, auth_service, test_user):
        """Test successful authentication with valid credentials."""
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = True
        
        result = await auth_service.authenticate(
            email=test_user.email,
            password="TestPass123!",
            ip_address=IpAddress("192.168.1.1"),
            user_agent=UserAgent("Mozilla/5.0"),
        )
        
        assert result.user == test_user
        assert result.access_token == "access_token"
        assert result.refresh_token == "refresh_token"
        assert result.expires_at > datetime.now(UTC)
        
        # Verify password was checked
        auth_service.password_service.verify_password.assert_called_once()
        
        # Verify login was recorded
        assert test_user.last_login_at is not None
        assert test_user.login_count == 1

    async def test_authenticate_with_invalid_password(self, auth_service, test_user):
        """Test authentication fails with invalid password."""
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = False
        
        with pytest.raises(InvalidCredentialsError) as exc_info:
            await auth_service.authenticate(
                email=test_user.email,
                password="WrongPassword",
                ip_address=IpAddress("192.168.1.1"),
                user_agent=UserAgent("Mozilla/5.0"),
            )
        
        assert "Invalid credentials" in str(exc_info.value)
        
        # Verify failed login was recorded
        assert test_user.failed_login_count == 1
        assert test_user.last_failed_login_at is not None

    async def test_authenticate_with_nonexistent_user(self, auth_service):
        """Test authentication fails for nonexistent user."""
        auth_service.user_repository.get_by_email.return_value = None
        
        with pytest.raises(InvalidCredentialsError) as exc_info:
            await auth_service.authenticate(
                email=Email("nonexistent@example.com"),
                password="TestPass123!",
                ip_address=IpAddress("192.168.1.1"),
                user_agent=UserAgent("Mozilla/5.0"),
            )
        
        assert "Invalid credentials" in str(exc_info.value)

    async def test_authenticate_with_inactive_account(self, auth_service, test_user):
        """Test authentication fails for inactive account."""
        test_user.deactivate("Test deactivation")
        auth_service.user_repository.get_by_email.return_value = test_user
        
        with pytest.raises(AccountNotActiveError) as exc_info:
            await auth_service.authenticate(
                email=test_user.email,
                password="TestPass123!",
                ip_address=IpAddress("192.168.1.1"),
                user_agent=UserAgent("Mozilla/5.0"),
            )
        
        assert "not active" in str(exc_info.value).lower()

    async def test_authenticate_with_locked_account(self, auth_service, test_user):
        """Test authentication fails for locked account."""
        test_user.lock("Too many failed attempts", datetime.now(UTC) + timedelta(hours=1))
        auth_service.user_repository.get_by_email.return_value = test_user
        
        with pytest.raises(AccountLockedError) as exc_info:
            await auth_service.authenticate(
                email=test_user.email,
                password="TestPass123!",
                ip_address=IpAddress("192.168.1.1"),
                user_agent=UserAgent("Mozilla/5.0"),
            )
        
        assert "locked" in str(exc_info.value).lower()
        assert exc_info.value.locked_until == test_user.locked_until

    async def test_authenticate_with_expired_lock(self, auth_service, test_user):
        """Test authentication succeeds when lock has expired."""
        # Lock with past expiration
        test_user.lock("Test lock", datetime.now(UTC) - timedelta(hours=1))
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = True
        
        result = await auth_service.authenticate(
            email=test_user.email,
            password="TestPass123!",
            ip_address=IpAddress("192.168.1.1"),
            user_agent=UserAgent("Mozilla/5.0"),
        )
        
        assert result.user == test_user
        assert not test_user.is_locked  # Should be automatically unlocked

    async def test_authenticate_with_pending_activation(self, auth_service):
        """Test authentication fails for pending activation account."""
        # Create user without activating
        user = User.create(
            email=Email("pending@example.com"),
            username=Username("pendinguser"),
            password_hash=PasswordHash.from_password("TestPass123!"),
        )
        auth_service.user_repository.get_by_email.return_value = user
        
        with pytest.raises(AccountNotActiveError) as exc_info:
            await auth_service.authenticate(
                email=user.email,
                password="TestPass123!",
                ip_address=IpAddress("192.168.1.1"),
                user_agent=UserAgent("Mozilla/5.0"),
            )
        
        assert "pending activation" in str(exc_info.value).lower()

    async def test_authenticate_tracks_device_info(self, auth_service, test_user):
        """Test authentication tracks device information."""
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = True
        
        ip_address = IpAddress("192.168.1.100")
        user_agent = UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        
        await auth_service.authenticate(
            email=test_user.email,
            password="TestPass123!",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        assert test_user.last_login_ip == str(ip_address.value)
        assert test_user.last_login_user_agent == str(user_agent.value)

    async def test_authenticate_with_rate_limiting(self, auth_service, test_user):
        """Test authentication enforces rate limiting after failed attempts."""
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = False
        
        # Simulate multiple failed attempts
        for _ in range(5):
            try:
                await auth_service.authenticate(
                    email=test_user.email,
                    password="WrongPassword",
                    ip_address=IpAddress("192.168.1.1"),
                    user_agent=UserAgent("Mozilla/5.0"),
                )
            except InvalidCredentialsError:
                pass
        
        # User should be locked after max attempts
        assert test_user.is_locked
        assert test_user.lock_reason == "Too many failed login attempts"

    async def test_validate_token_with_valid_token(self, auth_service):
        """Test token validation with valid token."""
        token_data = {
            "user_id": "123e4567-e89b-12d3-a456-426614174000",
            "email": "test@example.com",
            "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
        }
        auth_service.token_service.validate_token.return_value = token_data
        
        result = await auth_service.validate_token("valid_token")
        
        assert result == token_data
        auth_service.token_service.validate_token.assert_called_once_with("valid_token")

    async def test_validate_token_with_expired_token(self, auth_service):
        """Test token validation with expired token."""
        auth_service.token_service.validate_token.side_effect = AuthenticationError("Token expired")
        
        with pytest.raises(AuthenticationError) as exc_info:
            await auth_service.validate_token("expired_token")
        
        assert "expired" in str(exc_info.value).lower()

    async def test_refresh_token_with_valid_token(self, auth_service, test_user):
        """Test token refresh with valid refresh token."""
        auth_service.token_service.validate_refresh_token = Mock(
            return_value={"user_id": str(test_user.id), "token_id": "token123"}
        )
        auth_service.user_repository.get_by_id.return_value = test_user
        
        result = await auth_service.refresh_token("valid_refresh_token")
        
        assert result.access_token == "access_token"
        assert result.refresh_token == "refresh_token"
        assert result.user == test_user

    async def test_change_password(self, auth_service, test_user):
        """Test password change."""
        auth_service.user_repository.get_by_id.return_value = test_user
        auth_service.password_service.verify_password.return_value = True
        auth_service.password_service.validate_password.return_value = True
        
        new_password_hash = PasswordHash.from_password("NewSecurePass123!")
        auth_service.password_service.hash_password.return_value = new_password_hash
        
        await auth_service.change_password(
            user=test_user,
            current_password="TestPass123!",
            new_password="NewSecurePass123!",
        )
        
        assert test_user.password_hash == new_password_hash
        assert test_user.password_changed_at is not None
        
        # Verify password validation was called
        auth_service.password_service.validate_password.assert_called_once_with("NewSecurePass123!")

    async def test_change_password_with_wrong_current(self, auth_service, test_user):
        """Test password change fails with wrong current password."""
        auth_service.password_service.verify_password.return_value = False
        
        with pytest.raises(InvalidCredentialsError) as exc_info:
            await auth_service.change_password(
                user=test_user,
                current_password="WrongPassword",
                new_password="NewSecurePass123!",
            )
        
        assert "current password is incorrect" in str(exc_info.value).lower()

    async def test_reset_password(self, auth_service, test_user):
        """Test password reset (without current password check)."""
        auth_service.password_service.validate_password.return_value = True
        new_password_hash = PasswordHash.from_password("ResetPass123!")
        auth_service.password_service.hash_password.return_value = new_password_hash
        
        await auth_service.reset_password(
            user=test_user,
            new_password="ResetPass123!",
        )
        
        assert test_user.password_hash == new_password_hash
        assert test_user.password_changed_at is not None
        assert test_user.failed_login_count == 0  # Should be reset

    async def test_authenticate_with_mfa_required(self, auth_service, test_user):
        """Test authentication with MFA required."""
        test_user.enable_mfa()
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = True
        
        result = await auth_service.authenticate(
            email=test_user.email,
            password="TestPass123!",
            ip_address=IpAddress("192.168.1.1"),
            user_agent=UserAgent("Mozilla/5.0"),
        )
        
        assert result.mfa_required
        assert result.mfa_token is not None
        assert result.access_token is None  # Not issued until MFA completed

    async def test_logout(self, auth_service, test_user):
        """Test user logout."""
        session_id = "session123"
        
        await auth_service.logout(user=test_user, session_id=session_id)
        
        # Should invalidate tokens and update user
        auth_service.user_repository.save.assert_called_once_with(test_user)

    async def test_authenticate_creates_audit_trail(self, auth_service, test_user):
        """Test authentication creates proper audit trail."""
        auth_service.user_repository.get_by_email.return_value = test_user
        auth_service.password_service.verify_password.return_value = True
        
        await auth_service.authenticate(
            email=test_user.email,
            password="TestPass123!",
            ip_address=IpAddress("192.168.1.1"),
            user_agent=UserAgent("Mozilla/5.0"),
            context={"app": "mobile", "version": "1.0.0"}
        )
        
        # Check domain events were generated
        events = test_user.pull_domain_events()
        assert any(e.__class__.__name__ == "UserLoggedInEvent" for e in events)