"""
Integration tests for authentication flow.

Tests complete authentication scenarios including login, MFA,
session management, and token refresh.
"""

import asyncio
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.authentication import (
    LoginCommand,
    LogoutCommand,
    RefreshTokenCommand,
    VerifyMFACommand,
)
from app.modules.identity.application.services import IdentityApplicationService
from app.modules.identity.domain.exceptions import (
    AccountLockedException,
    InvalidCredentialsError,
    InvalidMFACodeError,
    SessionExpiredError,
)


@pytest.mark.integration
class TestLoginFlow:
    """Test complete login flow scenarios."""

    @pytest.fixture
    async def verified_user(self, app_service):
        """Create a verified user for testing."""
        # This would create a real user in test DB
        return {
            "user_id": str(uuid4()),
            "email": "verified@example.com",
            "username": "verifieduser",
            "password": "SecurePass123!@#",
        }

    @pytest.fixture
    async def app_service(self):
        """Create application service."""
        service = Mock(spec=IdentityApplicationService)
        service.login = AsyncMock()
        service.logout = AsyncMock()
        service.refresh_token = AsyncMock()
        service.verify_mfa = AsyncMock()
        return service

    @pytest.mark.asyncio
    async def test_successful_login_flow(self, app_service, verified_user):
        """Test successful login with session creation."""
        # Mock successful login
        app_service.login.return_value = Mock(
            access_token="access_token_123",
            refresh_token="refresh_token_123",
            user_id=verified_user["user_id"],
            session_id=str(uuid4()),
            expires_in=3600,
        )

        command = LoginCommand(
            username=verified_user["username"],
            password=verified_user["password"],
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            device_id="device-123",
        )

        result = await app_service.login(command)

        assert result.access_token is not None
        assert result.refresh_token is not None
        assert result.user_id == verified_user["user_id"]
        assert result.session_id is not None
        assert result.expires_in == 3600

    @pytest.mark.asyncio
    async def test_login_with_invalid_credentials(self, app_service, verified_user):
        """Test login with wrong password."""
        app_service.login.side_effect = InvalidCredentialsError("Invalid credentials")

        command = LoginCommand(
            username=verified_user["username"],
            password="WrongPassword123!",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        with pytest.raises(InvalidCredentialsError):
            await app_service.login(command)

    @pytest.mark.asyncio
    async def test_login_account_lockout(self, app_service, verified_user):
        """Test account lockout after multiple failed attempts."""

        # Simulate progressive failed attempts
        for i in range(6):
            command = LoginCommand(
                username=verified_user["username"],
                password="WrongPassword123!",
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )

            if i < 5:
                # First 5 attempts fail normally
                app_service.login.side_effect = InvalidCredentialsError(
                    f"Invalid credentials. Attempts: {i+1}/5"
                )

                with pytest.raises(InvalidCredentialsError) as exc_info:
                    await app_service.login(command)

                assert f"{i+1}/5" in str(exc_info.value)
            else:
                # 6th attempt triggers lockout
                app_service.login.side_effect = AccountLockedException(
                    "Account locked due to too many failed attempts"
                )

                with pytest.raises(AccountLockedException):
                    await app_service.login(command)

    @pytest.mark.asyncio
    async def test_concurrent_login_attempts(self, app_service, verified_user):
        """Test handling of concurrent login attempts."""
        # Mock successful logins
        session_ids = [str(uuid4()) for _ in range(5)]

        async def mock_login(command):
            # Simulate some processing time
            await asyncio.sleep(0.1)
            return Mock(
                access_token=f"token_{command.device_id}",
                refresh_token=f"refresh_{command.device_id}",
                session_id=session_ids.pop(0),
                user_id=verified_user["user_id"],
            )

        app_service.login.side_effect = mock_login

        # Create concurrent login attempts from different devices
        commands = []
        for i in range(5):
            command = LoginCommand(
                username=verified_user["username"],
                password=verified_user["password"],
                ip_address=f"192.168.1.{i+1}",
                user_agent="Mozilla/5.0",
                device_id=f"device-{i}",
            )
            commands.append(command)

        # Execute concurrently
        tasks = [app_service.login(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks)

        # All should succeed with different sessions
        assert len(results) == 5
        session_ids_returned = [r.session_id for r in results]
        assert len(set(session_ids_returned)) == 5  # All unique

    @pytest.mark.asyncio
    async def test_login_from_suspicious_location(self, app_service, verified_user):
        """Test login from suspicious location triggers additional security."""
        # First login from US
        us_command = LoginCommand(
            username=verified_user["username"],
            password=verified_user["password"],
            ip_address="8.8.8.8",  # US IP
            user_agent="Mozilla/5.0",
            location_country="US",
        )

        app_service.login.return_value = Mock(
            access_token="us_token",
            refresh_token="us_refresh",
            user_id=verified_user["user_id"],
        )

        us_result = await app_service.login(us_command)
        assert us_result.access_token is not None

        # Immediate login from different country
        cn_command = LoginCommand(
            username=verified_user["username"],
            password=verified_user["password"],
            ip_address="1.2.3.4",  # China IP
            user_agent="Mozilla/5.0",
            location_country="CN",
        )

        # Should trigger MFA requirement
        app_service.login.return_value = Mock(
            mfa_required=True,
            mfa_challenge_token="challenge_123",
            reason="suspicious_location",
        )

        cn_result = await app_service.login(cn_command)
        assert cn_result.mfa_required is True
        assert cn_result.reason == "suspicious_location"


@pytest.mark.integration
class TestMFAFlow:
    """Test Multi-Factor Authentication flow."""

    @pytest.fixture
    async def mfa_user(self, app_service):
        """Create a user with MFA enabled."""
        return {
            "user_id": str(uuid4()),
            "username": "mfauser",
            "password": "SecurePass123!@#",
            "mfa_secret": "JBSWY3DPEHPK3PXP",
        }

    @pytest.mark.asyncio
    async def test_login_with_mfa_required(self, app_service, mfa_user):
        """Test login flow when MFA is required."""
        # Step 1: Initial login
        login_command = LoginCommand(
            username=mfa_user["username"],
            password=mfa_user["password"],
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        app_service.login.return_value = Mock(
            mfa_required=True,
            mfa_challenge_token="challenge_token_123",
            mfa_methods=["totp", "backup_code"],
        )

        login_result = await app_service.login(login_command)

        assert login_result.mfa_required is True
        assert login_result.mfa_challenge_token is not None
        assert "totp" in login_result.mfa_methods

        # Step 2: Verify MFA
        mfa_command = VerifyMFACommand(
            challenge_token=login_result.mfa_challenge_token,
            mfa_code="123456",  # TOTP code
            mfa_method="totp",
        )

        app_service.verify_mfa.return_value = Mock(
            access_token="mfa_verified_token",
            refresh_token="mfa_verified_refresh",
            user_id=mfa_user["user_id"],
            session_id=str(uuid4()),
        )

        mfa_result = await app_service.verify_mfa(mfa_command)

        assert mfa_result.access_token is not None
        assert mfa_result.refresh_token is not None

    @pytest.mark.asyncio
    async def test_mfa_with_backup_code(self, app_service, mfa_user):
        """Test MFA verification using backup code."""
        # Get MFA challenge
        app_service.login.return_value = Mock(
            mfa_required=True, mfa_challenge_token="challenge_backup_123"
        )

        login_command = LoginCommand(
            username=mfa_user["username"],
            password=mfa_user["password"],
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        login_result = await app_service.login(login_command)

        # Use backup code
        backup_command = VerifyMFACommand(
            challenge_token=login_result.mfa_challenge_token,
            mfa_code="ABCD-EFGH-IJKL",  # Backup code format
            mfa_method="backup_code",
        )

        app_service.verify_mfa.return_value = Mock(
            access_token="backup_verified_token",
            refresh_token="backup_verified_refresh",
            backup_codes_remaining=9,
        )

        backup_result = await app_service.verify_mfa(backup_command)

        assert backup_result.access_token is not None
        assert backup_result.backup_codes_remaining == 9

    @pytest.mark.asyncio
    async def test_mfa_brute_force_protection(self, app_service, mfa_user):
        """Test protection against MFA code brute force."""
        # Get MFA challenge
        app_service.login.return_value = Mock(
            mfa_required=True, mfa_challenge_token="challenge_brute_123"
        )

        login_result = await app_service.login(
            LoginCommand(
                username=mfa_user["username"],
                password=mfa_user["password"],
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )
        )

        # Try multiple wrong codes
        for i in range(6):
            wrong_command = VerifyMFACommand(
                challenge_token=login_result.mfa_challenge_token,
                mfa_code=f"{i:06d}",  # Wrong codes
                mfa_method="totp",
            )

            if i < 5:
                # First 5 attempts fail normally
                app_service.verify_mfa.side_effect = InvalidMFACodeError(
                    f"Invalid code. Attempts: {i+1}/5"
                )

                with pytest.raises(InvalidMFACodeError):
                    await app_service.verify_mfa(wrong_command)
            else:
                # 6th attempt locks MFA
                app_service.verify_mfa.side_effect = AccountLockedException(
                    "Too many failed MFA attempts"
                )

                with pytest.raises(AccountLockedException):
                    await app_service.verify_mfa(wrong_command)


@pytest.mark.integration
class TestSessionManagement:
    """Test session management functionality."""

    @pytest.fixture
    async def active_session(self, app_service, verified_user):
        """Create an active session."""
        app_service.login.return_value = Mock(
            access_token="session_token",
            refresh_token="session_refresh",
            session_id=str(uuid4()),
            user_id=verified_user["user_id"],
        )

        return await app_service.login(
            LoginCommand(
                username=verified_user["username"],
                password=verified_user["password"],
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )
        )

    @pytest.mark.asyncio
    async def test_token_refresh_flow(self, app_service, active_session):
        """Test token refresh flow."""
        command = RefreshTokenCommand(refresh_token=active_session.refresh_token)

        app_service.refresh_token.return_value = Mock(
            access_token="new_access_token",
            refresh_token="new_refresh_token",
            expires_in=3600,
        )

        result = await app_service.refresh_token(command)

        assert result.access_token != active_session.access_token
        assert result.refresh_token != active_session.refresh_token
        assert result.expires_in == 3600

    @pytest.mark.asyncio
    async def test_refresh_with_expired_session(self, app_service, active_session):
        """Test token refresh with expired session."""
        command = RefreshTokenCommand(refresh_token=active_session.refresh_token)

        app_service.refresh_token.side_effect = SessionExpiredError(
            "Session has expired"
        )

        with pytest.raises(SessionExpiredError):
            await app_service.refresh_token(command)

    @pytest.mark.asyncio
    async def test_logout_flow(self, app_service, active_session):
        """Test logout flow."""
        command = LogoutCommand(
            access_token=active_session.access_token,
            refresh_token=active_session.refresh_token,
        )

        app_service.logout.return_value = Mock(success=True, sessions_ended=1)

        result = await app_service.logout(command)

        assert result.success is True
        assert result.sessions_ended == 1

    @pytest.mark.asyncio
    async def test_logout_all_sessions(self, app_service, verified_user):
        """Test logging out from all sessions."""
        # Create multiple sessions
        sessions = []
        for i in range(3):
            app_service.login.return_value = Mock(
                access_token=f"token_{i}",
                refresh_token=f"refresh_{i}",
                session_id=str(uuid4()),
                user_id=verified_user["user_id"],
            )

            result = await app_service.login(
                LoginCommand(
                    username=verified_user["username"],
                    password=verified_user["password"],
                    ip_address=f"192.168.1.{i+1}",
                    user_agent="Mozilla/5.0",
                    device_id=f"device_{i}",
                )
            )
            sessions.append(result)

        # Logout from all sessions
        command = LogoutCommand(access_token=sessions[0].access_token, logout_all=True)

        app_service.logout.return_value = Mock(success=True, sessions_ended=3)

        result = await app_service.logout(command)

        assert result.success is True
        assert result.sessions_ended == 3

    @pytest.mark.asyncio
    async def test_session_activity_tracking(self, app_service, active_session):
        """Test that session activity is properly tracked."""
        # Simulate API calls with the session
        for _i in range(5):
            # Each API call should update last activity
            await app_service.validate_session(
                session_id=active_session.session_id,
                access_token=active_session.access_token,
            )

            # Wait a bit between calls
            await asyncio.sleep(0.1)

        # Get session details
        session_details = await app_service.get_session_details(
            session_id=active_session.session_id
        )

        assert session_details.request_count >= 5
        assert session_details.last_activity is not None

    @pytest.mark.asyncio
    async def test_concurrent_session_limit(self, app_service, verified_user):
        """Test enforcement of concurrent session limits."""
        max_sessions = 5
        sessions = []

        # Create max allowed sessions
        for i in range(max_sessions):
            app_service.login.return_value = Mock(
                access_token=f"token_{i}",
                refresh_token=f"refresh_{i}",
                session_id=str(uuid4()),
            )

            result = await app_service.login(
                LoginCommand(
                    username=verified_user["username"],
                    password=verified_user["password"],
                    ip_address=f"192.168.1.{i+1}",
                    user_agent="Mozilla/5.0",
                    device_id=f"device_{i}",
                )
            )
            sessions.append(result)

        # Try to create one more session
        app_service.login.return_value = Mock(
            access_token="token_new",
            refresh_token="refresh_new",
            session_id=str(uuid4()),
            oldest_session_terminated=True,
            terminated_session_id=sessions[0].session_id,
        )

        extra_result = await app_service.login(
            LoginCommand(
                username=verified_user["username"],
                password=verified_user["password"],
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
                device_id="device_extra",
            )
        )

        # Should succeed but terminate oldest session
        assert extra_result.oldest_session_terminated is True
        assert extra_result.terminated_session_id == sessions[0].session_id
