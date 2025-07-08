"""
Test cases for authentication command and query handlers.

Tests all authentication-related handlers including login, logout,
token refresh, and session management.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.authentication import (
    LoginCommand,
    LoginCommandHandler,
    LogoutCommand,
    LogoutCommandHandler,
    RefreshTokenCommand,
    RefreshTokenCommandHandler,
    ValidateSessionCommand,
    ValidateSessionCommandHandler,
)
from app.modules.identity.application.queries.authentication import (
    GetActiveSessionsQuery,
    GetActiveSessionsQueryHandler,
)
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.exceptions import (
    AccountLockedException,
    InvalidCredentialsError,
    InvalidTokenError,
    SessionExpiredError,
)
from app.modules.identity.domain.value_objects import IpAddress, UserAgent


class TestLoginCommandHandler:
    """Test login command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_session_repo = Mock()
        mock_token_service = Mock()
        mock_password_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return LoginCommandHandler(
            user_repository=mock_user_repo,
            session_repository=mock_session_repo,
            token_service=mock_token_service,
            password_service=mock_password_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_login_with_username(self, handler):
        """Test successful login with username."""
        # Arrange
        user_id = str(uuid4())
        user = Mock(spec=User)
        user.id = user_id
        user.is_active = True
        user.is_locked = False
        user.failed_login_count = 0
        user.validate_password = Mock(return_value=True)
        user.record_successful_login = Mock()

        handler.user_repository.find_by_username = AsyncMock(return_value=user)
        handler.session_repository.save = AsyncMock()
        handler.token_service.generate_access_token = Mock(return_value="access_token")
        handler.token_service.generate_refresh_token = Mock(
            return_value="refresh_token"
        )

        command = LoginCommand(
            username="testuser",
            password="Test123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
            device_id="device-123",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.access_token == "access_token"
        assert result.refresh_token == "refresh_token"
        assert result.user_id == user_id
        assert result.session_id is not None

        handler.user_repository.find_by_username.assert_called_once()
        handler.session_repository.save.assert_called_once()
        user.record_successful_login.assert_called_once()

    @pytest.mark.asyncio
    async def test_successful_login_with_email(self, handler):
        """Test successful login with email."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.is_active = True
        user.is_locked = False
        user.validate_password = Mock(return_value=True)
        user.record_successful_login = Mock()

        handler.user_repository.find_by_email = AsyncMock(return_value=user)
        handler.session_repository.save = AsyncMock()
        handler.token_service.generate_access_token = Mock(return_value="access_token")
        handler.token_service.generate_refresh_token = Mock(
            return_value="refresh_token"
        )

        command = LoginCommand(
            email="user@example.com",
            password="Test123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.access_token == "access_token"
        handler.user_repository.find_by_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_login_with_invalid_credentials(self, handler):
        """Test login with invalid credentials."""
        # Arrange
        user = Mock(spec=User)
        user.is_active = True
        user.is_locked = False
        user.validate_password = Mock(return_value=False)
        user.record_failed_login = Mock()

        handler.user_repository.find_by_username = AsyncMock(return_value=user)
        handler.user_repository.save = AsyncMock()

        command = LoginCommand(
            username="testuser",
            password="wrongpassword",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
        )

        # Act & Assert
        with pytest.raises(InvalidCredentialsError):
            await handler.handle(command)

        user.record_failed_login.assert_called_once()
        handler.user_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_login_with_locked_account(self, handler):
        """Test login with locked account."""
        # Arrange
        user = Mock(spec=User)
        user.is_active = True
        user.is_locked = True
        user.locked_until = datetime.now(UTC) + timedelta(hours=1)

        handler.user_repository.find_by_username = AsyncMock(return_value=user)

        command = LoginCommand(
            username="testuser",
            password="Test123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
        )

        # Act & Assert
        with pytest.raises(AccountLockedException):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_login_with_mfa_required(self, handler):
        """Test login when MFA is required."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.is_active = True
        user.is_locked = False
        user.mfa_enabled = True
        user.validate_password = Mock(return_value=True)
        user.generate_mfa_challenge = Mock(return_value="challenge_token")

        handler.user_repository.find_by_username = AsyncMock(return_value=user)
        handler.session_repository.save = AsyncMock()

        command = LoginCommand(
            username="testuser",
            password="Test123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.mfa_required is True
        assert result.mfa_challenge_token == "challenge_token"
        assert result.access_token is None
        assert result.refresh_token is None

    @pytest.mark.asyncio
    async def test_login_with_device_trust(self, handler):
        """Test login with trusted device."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.is_active = True
        user.is_locked = False
        user.mfa_enabled = True
        user.validate_password = Mock(return_value=True)
        user.is_device_trusted = Mock(return_value=True)
        user.record_successful_login = Mock()

        handler.user_repository.find_by_username = AsyncMock(return_value=user)
        handler.session_repository.save = AsyncMock()
        handler.token_service.generate_access_token = Mock(return_value="access_token")
        handler.token_service.generate_refresh_token = Mock(
            return_value="refresh_token"
        )

        command = LoginCommand(
            username="testuser",
            password="Test123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
            device_id="trusted-device-123",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.mfa_required is False  # Skipped due to trusted device
        assert result.access_token == "access_token"


class TestLogoutCommandHandler:
    """Test logout command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_session_repo = Mock()
        mock_token_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return LogoutCommandHandler(
            session_repository=mock_session_repo,
            token_service=mock_token_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_logout(self, handler):
        """Test successful logout."""
        # Arrange
        session = Mock(spec=Session)
        session.id = str(uuid4())
        session.user_id = str(uuid4())
        session.is_active = True
        session.end = Mock()

        handler.session_repository.find_by_token = AsyncMock(return_value=session)
        handler.session_repository.save = AsyncMock()
        handler.token_service.revoke_token = AsyncMock()

        command = LogoutCommand(
            access_token="valid_token", refresh_token="refresh_token"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        session.end.assert_called_once()
        handler.session_repository.save.assert_called_once()
        handler.token_service.revoke_token.assert_called()

    @pytest.mark.asyncio
    async def test_logout_with_invalid_token(self, handler):
        """Test logout with invalid token."""
        # Arrange
        handler.session_repository.find_by_token = AsyncMock(return_value=None)

        command = LogoutCommand(access_token="invalid_token")

        # Act & Assert
        with pytest.raises(InvalidTokenError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_logout_all_sessions(self, handler):
        """Test logout from all sessions."""
        # Arrange
        sessions = [Mock(spec=Session) for _ in range(3)]
        for session in sessions:
            session.end = Mock()

        handler.session_repository.find_active_by_user = AsyncMock(
            return_value=sessions
        )
        handler.session_repository.save_many = AsyncMock()
        handler.token_service.revoke_all_user_tokens = AsyncMock()

        command = LogoutCommand(
            access_token="valid_token", logout_all=True, user_id=str(uuid4())
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.sessions_ended == 3
        for session in sessions:
            session.end.assert_called_once()


class TestRefreshTokenCommandHandler:
    """Test refresh token command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_session_repo = Mock()
        mock_user_repo = Mock()
        mock_token_service = Mock()
        mock_event_bus = Mock()

        return RefreshTokenCommandHandler(
            session_repository=mock_session_repo,
            user_repository=mock_user_repo,
            token_service=mock_token_service,
            event_bus=mock_event_bus,
        )

    @pytest.mark.asyncio
    async def test_successful_token_refresh(self, handler):
        """Test successful token refresh."""
        # Arrange
        user_id = str(uuid4())
        session_id = str(uuid4())

        handler.token_service.validate_refresh_token = Mock(
            return_value={"user_id": user_id, "session_id": session_id}
        )

        session = Mock(spec=Session)
        session.is_active = True
        session.user_id = user_id
        session.refresh = Mock()

        user = Mock(spec=User)
        user.is_active = True
        user.is_locked = False

        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.session_repository.save = AsyncMock()
        handler.token_service.generate_access_token = Mock(
            return_value="new_access_token"
        )
        handler.token_service.generate_refresh_token = Mock(
            return_value="new_refresh_token"
        )

        command = RefreshTokenCommand(refresh_token="valid_refresh_token")

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.access_token == "new_access_token"
        assert result.refresh_token == "new_refresh_token"
        session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_refresh_with_expired_session(self, handler):
        """Test refresh with expired session."""
        # Arrange
        handler.token_service.validate_refresh_token = Mock(
            return_value={"user_id": str(uuid4()), "session_id": str(uuid4())}
        )

        session = Mock(spec=Session)
        session.is_active = False  # Expired

        handler.session_repository.find_by_id = AsyncMock(return_value=session)

        command = RefreshTokenCommand(refresh_token="valid_refresh_token")

        # Act & Assert
        with pytest.raises(SessionExpiredError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_refresh_with_rotation(self, handler):
        """Test token refresh with rotation."""
        # Arrange
        user_id = str(uuid4())
        session_id = str(uuid4())

        handler.token_service.validate_refresh_token = Mock(
            return_value={"user_id": user_id, "session_id": session_id}
        )
        handler.token_service.should_rotate_refresh_token = Mock(return_value=True)

        session = Mock(spec=Session)
        session.is_active = True
        session.user_id = user_id
        session.refresh = Mock()
        session.rotate_refresh_token = Mock()

        user = Mock(spec=User)
        user.is_active = True

        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.session_repository.save = AsyncMock()
        handler.token_service.generate_access_token = Mock(
            return_value="new_access_token"
        )
        handler.token_service.generate_refresh_token = Mock(
            return_value="rotated_refresh_token"
        )

        command = RefreshTokenCommand(refresh_token="valid_refresh_token")

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.refresh_token == "rotated_refresh_token"
        session.rotate_refresh_token.assert_called_once()


class TestGetActiveSessionsQueryHandler:
    """Test get active sessions query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_session_repo = Mock()
        mock_cache = Mock()

        return GetActiveSessionsQueryHandler(
            session_repository=mock_session_repo, cache=mock_cache
        )

    @pytest.mark.asyncio
    async def test_get_user_active_sessions(self, handler):
        """Test getting user's active sessions."""
        # Arrange
        user_id = str(uuid4())
        sessions = []

        for i in range(3):
            session = Mock(spec=Session)
            session.id = str(uuid4())
            session.user_id = user_id
            session.ip_address = IpAddress(f"192.168.1.{i+1}")
            session.user_agent = UserAgent.parse("Mozilla/5.0...")
            session.created_at = datetime.now(UTC) - timedelta(hours=i)
            session.last_activity = datetime.now(UTC) - timedelta(minutes=i * 10)
            session.is_active = True
            sessions.append(session)

        handler.cache.get = Mock(return_value=None)
        handler.session_repository.find_active_by_user = AsyncMock(
            return_value=sessions
        )
        handler.cache.set = Mock()

        query = GetActiveSessionsQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.sessions) == 3
        assert result.total_count == 3
        assert all(s.is_active for s in result.sessions)
        handler.session_repository.find_active_by_user.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_get_sessions_with_cache_hit(self, handler):
        """Test getting sessions from cache."""
        # Arrange
        user_id = str(uuid4())
        cached_data = {
            "sessions": [
                {
                    "id": str(uuid4()),
                    "ip_address": "192.168.1.1",
                    "device_name": "Chrome on Windows",
                    "last_activity": datetime.now(UTC).isoformat(),
                }
            ],
            "total_count": 1,
        }

        handler.cache.get = Mock(return_value=cached_data)

        query = GetActiveSessionsQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.sessions) == 1
        handler.session_repository.find_active_by_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_sessions_with_pagination(self, handler):
        """Test getting sessions with pagination."""
        # Arrange
        user_id = str(uuid4())
        total_sessions = 10
        page_size = 3

        sessions = []
        for i in range(page_size):
            session = Mock(spec=Session)
            session.id = str(uuid4())
            session.last_activity = datetime.now(UTC) - timedelta(minutes=i * 10)
            sessions.append(session)

        handler.cache.get = Mock(return_value=None)
        handler.session_repository.find_active_by_user = AsyncMock(
            return_value=sessions
        )
        handler.session_repository.count_active_by_user = AsyncMock(
            return_value=total_sessions
        )
        handler.cache.set = Mock()

        query = GetActiveSessionsQuery(user_id=user_id, page=2, page_size=page_size)

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.sessions) == page_size
        assert result.total_count == total_sessions
        assert result.page == 2
        assert result.page_size == page_size
        assert result.total_pages == 4  # ceil(10/3)


class TestValidateSessionCommandHandler:
    """Test validate session command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_session_repo = Mock()
        mock_user_repo = Mock()
        mock_risk_analyzer = Mock()

        return ValidateSessionCommandHandler(
            session_repository=mock_session_repo,
            user_repository=mock_user_repo,
            risk_analyzer=mock_risk_analyzer,
        )

    @pytest.mark.asyncio
    async def test_validate_active_session(self, handler):
        """Test validating an active session."""
        # Arrange
        session = Mock(spec=Session)
        session.id = str(uuid4())
        session.user_id = str(uuid4())
        session.is_active = True
        session.is_expired = Mock(return_value=False)
        session.record_activity = Mock()

        user = Mock(spec=User)
        user.is_active = True
        user.is_locked = False

        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.risk_analyzer.analyze_session = AsyncMock(
            return_value={"risk_level": "low"}
        )
        handler.session_repository.save = AsyncMock()

        command = ValidateSessionCommand(
            session_id=session.id, ip_address="192.168.1.1", user_agent="Mozilla/5.0..."
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.is_valid is True
        assert result.risk_level == "low"
        session.record_activity.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_expired_session(self, handler):
        """Test validating an expired session."""
        # Arrange
        session = Mock(spec=Session)
        session.is_active = True
        session.is_expired = Mock(return_value=True)

        handler.session_repository.find_by_id = AsyncMock(return_value=session)

        command = ValidateSessionCommand(
            session_id=str(uuid4()),
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.is_valid is False
        assert result.reason == "session_expired"

    @pytest.mark.asyncio
    async def test_validate_session_with_ip_change(self, handler):
        """Test validating session with IP address change."""
        # Arrange
        session = Mock(spec=Session)
        session.id = str(uuid4())
        session.user_id = str(uuid4())
        session.is_active = True
        session.is_expired = Mock(return_value=False)
        session.ip_address = IpAddress("192.168.1.1")

        user = Mock(spec=User)
        user.is_active = True

        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.risk_analyzer.analyze_session = AsyncMock(
            return_value={
                "risk_level": "high",
                "factors": ["ip_change", "location_change"],
            }
        )

        command = ValidateSessionCommand(
            session_id=session.id,
            ip_address="10.0.0.1",  # Different IP
            user_agent="Mozilla/5.0...",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.is_valid is True  # Still valid but high risk
        assert result.risk_level == "high"
        assert "ip_change" in result.risk_factors
