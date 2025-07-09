"""
Comprehensive unit tests for UserLoginCommand and handler.

Tests cover:
- Login flow with valid credentials
- Failed login attempts
- Account status checks
- MFA requirements
- Session creation
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest

from app.modules.identity.application.commands.user_commands import (
    LoginCommand,
    LoginCommandHandler,
)
from app.modules.identity.application.errors import ValidationError
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.errors import (
    AccountLockedError,
    AccountNotActiveError,
    AuthenticationError,
    InvalidCredentialsError,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.username import Username


class TestUserLoginCommand:
    """Test suite for user login command and handler."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        repo = AsyncMock()
        return repo

    @pytest.fixture
    def mock_auth_service(self):
        """Create mock authentication service."""
        service = AsyncMock()
        return service

    @pytest.fixture
    def mock_session_repository(self):
        """Create mock session repository."""
        repo = AsyncMock()
        return repo

    @pytest.fixture
    def mock_event_bus(self):
        """Create mock event bus."""
        bus = AsyncMock()
        return bus

    @pytest.fixture
    def mock_rate_limiter(self):
        """Create mock rate limiter."""
        limiter = AsyncMock()
        limiter.check_rate_limit.return_value = True
        return limiter

    @pytest.fixture
    def command_handler(
        self,
        mock_user_repository,
        mock_auth_service,
        mock_session_repository,
        mock_event_bus,
        mock_rate_limiter,
    ):
        """Create command handler with dependencies."""
        return LoginCommandHandler(
            user_repository=mock_user_repository,
            auth_service=mock_auth_service,
            session_repository=mock_session_repository,
            event_bus=mock_event_bus,
            rate_limiter=mock_rate_limiter,
        )

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user = User.create(
            email=Email("user@example.com"),
            username=Username("testuser"),
            password_hash=PasswordHash.from_password("TestPass123!"),
        )
        user.activate()
        user.pull_domain_events()  # Clear events
        return user

    def test_create_login_command(self):
        """Test creating login command with valid data."""
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_name="Chrome on Windows",
            remember_me=True,
        )
        
        assert command.email == "user@example.com"
        assert command.password == "TestPass123!"
        assert command.ip_address == "192.168.1.1"
        assert command.user_agent == "Mozilla/5.0"
        assert command.device_name == "Chrome on Windows"
        assert command.remember_me is True

    def test_login_command_validation(self):
        """Test login command validation."""
        # Missing email
        with pytest.raises(ValidationError):
            LoginCommand(
                email="",
                password="TestPass123!",
                ip_address="192.168.1.1",
            )
        
        # Missing password
        with pytest.raises(ValidationError):
            LoginCommand(
                email="user@example.com",
                password="",
                ip_address="192.168.1.1",
            )
        
        # Invalid IP address
        with pytest.raises(ValidationError):
            LoginCommand(
                email="user@example.com",
                password="TestPass123!",
                ip_address="invalid-ip",
            )

    async def test_successful_login(self, command_handler, test_user):
        """Test successful login flow."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="access_token_123",
            refresh_token="refresh_token_123",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            mfa_required=False,
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )
        
        result = await command_handler.handle(command)
        
        assert result.success is True
        assert result.access_token == "access_token_123"
        assert result.refresh_token == "refresh_token_123"
        assert result.user_id == str(test_user.id)
        assert result.mfa_required is False
        
        # Verify auth service was called
        command_handler.auth_service.authenticate.assert_called_once()
        
        # Verify session was saved
        command_handler.session_repository.save.assert_called_once()
        
        # Verify events were published
        command_handler.event_bus.publish_batch.assert_called_once()

    async def test_login_with_invalid_credentials(self, command_handler):
        """Test login with invalid credentials."""
        command_handler.user_repository.get_by_email.return_value = None
        
        command = LoginCommand(
            email="nonexistent@example.com",
            password="WrongPass123!",
            ip_address="192.168.1.1",
        )
        
        with pytest.raises(InvalidCredentialsError):
            await command_handler.handle(command)
        
        # Should not create session
        command_handler.session_repository.save.assert_not_called()

    async def test_login_with_wrong_password(self, command_handler, test_user):
        """Test login with wrong password."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.side_effect = InvalidCredentialsError(
            "Invalid password"
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="WrongPassword!",
            ip_address="192.168.1.1",
        )
        
        with pytest.raises(InvalidCredentialsError):
            await command_handler.handle(command)

    async def test_login_with_inactive_account(self, command_handler, test_user):
        """Test login with inactive account."""
        test_user.deactivate("Test")
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.side_effect = AccountNotActiveError(
            "Account is inactive"
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
        )
        
        with pytest.raises(AccountNotActiveError):
            await command_handler.handle(command)

    async def test_login_with_locked_account(self, command_handler, test_user):
        """Test login with locked account."""
        test_user.lock("Too many attempts", datetime.now(UTC) + timedelta(hours=1))
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.side_effect = AccountLockedError(
            "Account is locked",
            locked_until=test_user.locked_until,
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
        )
        
        with pytest.raises(AccountLockedError) as exc_info:
            await command_handler.handle(command)
        
        assert exc_info.value.locked_until == test_user.locked_until

    async def test_login_with_mfa_required(self, command_handler, test_user):
        """Test login when MFA is required."""
        test_user.enable_mfa()
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token=None,
            refresh_token=None,
            mfa_required=True,
            mfa_token="mfa_token_123",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
        )
        
        result = await command_handler.handle(command)
        
        assert result.success is True
        assert result.mfa_required is True
        assert result.mfa_token == "mfa_token_123"
        assert result.access_token is None
        assert result.refresh_token is None

    async def test_login_with_remember_me(self, command_handler, test_user):
        """Test login with remember me option."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="access_token",
            refresh_token="refresh_token",
            expires_at=datetime.now(UTC) + timedelta(days=30),  # Extended expiry
            mfa_required=False,
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
            remember_me=True,
        )
        
        result = await command_handler.handle(command)
        
        assert result.success is True
        assert result.expires_in > 3600  # Longer than 1 hour

    async def test_login_rate_limiting(self, command_handler):
        """Test login rate limiting."""
        command_handler.rate_limiter.check_rate_limit.return_value = False
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            await command_handler.handle(command)
        
        assert "rate limit" in str(exc_info.value).lower()

    async def test_login_tracks_device_info(self, command_handler, test_user):
        """Test that login tracks device information."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            mfa_required=False,
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1)",
            device_name="iPhone 12",
            device_fingerprint="abc123def456",
        )
        
        await command_handler.handle(command)
        
        # Verify session includes device info
        saved_session = command_handler.session_repository.save.call_args[0][0]
        assert saved_session.device_name == "iPhone 12"
        assert saved_session.device_fingerprint == "abc123def456"

    async def test_login_with_geolocation(self, command_handler, test_user):
        """Test login with geolocation tracking."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            mfa_required=False,
        )
        
        # Mock geolocation service
        command_handler.geolocation_service = AsyncMock()
        command_handler.geolocation_service.get_location.return_value = {
            "country": "US",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060,
        }
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="8.8.8.8",
        )
        
        await command_handler.handle(command)
        
        # Verify location was tracked
        saved_session = command_handler.session_repository.save.call_args[0][0]
        assert saved_session.location["country"] == "US"
        assert saved_session.location["city"] == "New York"

    async def test_login_security_alerts(self, command_handler, test_user):
        """Test security alerts for suspicious login."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            mfa_required=False,
        )
        
        # Mock security service
        command_handler.security_service = AsyncMock()
        command_handler.security_service.check_suspicious_activity.return_value = True
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.100.1",  # Different from usual
        )
        
        await command_handler.handle(command)
        
        # Verify security alert was sent
        command_handler.security_service.send_security_alert.assert_called_once()

    async def test_concurrent_session_limit(self, command_handler, test_user):
        """Test concurrent session limit enforcement."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            mfa_required=False,
        )
        
        # Mock existing sessions
        command_handler.session_repository.count_active_sessions.return_value = 5
        command_handler.max_concurrent_sessions = 5
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
        )
        
        result = await command_handler.handle(command)
        
        # Should succeed but revoke oldest session
        assert result.success is True
        command_handler.session_repository.revoke_oldest_session.assert_called_once_with(
            test_user.id
        )

    async def test_login_audit_trail(self, command_handler, test_user):
        """Test that login creates proper audit trail."""
        command_handler.user_repository.get_by_email.return_value = test_user
        command_handler.auth_service.authenticate.return_value = Mock(
            user=test_user,
            access_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            mfa_required=False,
        )
        
        command = LoginCommand(
            email="user@example.com",
            password="TestPass123!",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={
                "app_version": "1.0.0",
                "platform": "web",
            }
        )
        
        await command_handler.handle(command)
        
        # Verify audit event includes metadata
        events = command_handler.event_bus.publish_batch.call_args[0][0]
        login_event = next(e for e in events if e.__class__.__name__ == "UserLoggedInEvent")
        assert login_event.metadata["ip_address"] == "192.168.1.1"
        assert login_event.metadata["user_agent"] == "Mozilla/5.0"
        assert login_event.payload["app_version"] == "1.0.0"