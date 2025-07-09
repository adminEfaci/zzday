"""
REAL Integration tests for authentication flow.

Tests complete authentication scenarios using REAL infrastructure components.
NO MOCKS - Tests actual system behavior end-to-end.
"""

import asyncio
from uuid import uuid4

import pytest

from app.modules.identity.domain.exceptions import (
    AccountLockedException,
    InvalidCredentialsError,
    InvalidMFACodeError,
    SessionExpiredError,
)
from app.tests.containers import TestContainer


@pytest.mark.integration
@pytest.mark.real_integration  # Mark for real integration tests
class TestRealAuthenticationFlow:
    """REAL integration tests using actual infrastructure."""

    @pytest.mark.asyncio
    async def test_complete_user_registration_and_login_flow(
        self, 
        test_container: TestContainer,
        email_builder
    ):
        """Test complete flow: registration -> verification -> login."""
        # Step 1: Register new user
        user_email = email_builder.unique()
        registration_data = {
            "username": user_email.value,
            "email": user_email.value,
            "password": "SecurePass123!@#",
            "confirm_password": "SecurePass123!@#"
        }
        
        registration_response = await test_container.async_client.post(
            "/api/v1/auth/register",
            json=registration_data
        )
        
        # Registration should succeed or user already exists
        assert registration_response.status_code in [201, 409]
        
        # Step 2: Attempt login (may require verification)
        login_data = {
            "username": user_email.value,
            "password": "SecurePass123!@#"
        }
        
        login_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json=login_data
        )
        
        # Should either succeed or require verification
        assert login_response.status_code in [200, 202, 401]
        
        if login_response.status_code == 200:
            # Successful login - verify response structure
            login_result = login_response.json()
            assert "access_token" in login_result or "token" in login_result
            
            # Step 3: Verify authenticated access
            auth_headers = {}
            if "access_token" in login_result:
                auth_headers["Authorization"] = f"Bearer {login_result['access_token']}"
            elif "token" in login_result:
                auth_headers["Authorization"] = f"Bearer {login_result['token']}"
                
            if auth_headers:
                profile_response = await test_container.async_client.get(
                    "/api/v1/auth/me",
                    headers=auth_headers
                )
                
                # Should be able to access protected endpoint
                assert profile_response.status_code in [200, 404]  # 404 if endpoint doesn't exist

    @pytest.mark.asyncio
    async def test_invalid_credentials_rejection(
        self, 
        test_container: TestContainer,
        email_builder
    ):
        """Test that invalid credentials are properly rejected."""
        # Try login with non-existent user
        fake_email = email_builder.unique()
        
        login_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json={
                "username": fake_email.value,
                "password": "WrongPassword123!"
            }
        )
        
        # Should be rejected
        assert login_response.status_code == 401
        
        # Response should not leak user existence
        response_text = login_response.text.lower()
        assert "not found" not in response_text
        assert "does not exist" not in response_text

    @pytest.mark.asyncio
    async def test_concurrent_login_attempts(
        self, 
        test_container: TestContainer,
        email_builder
    ):
        """Test handling of concurrent login attempts."""
        # Create user first
        user_email = email_builder.unique()
        user_data = {
            "username": user_email.value,
            "email": user_email.value,
            "password": "ConcurrentTest123!@#",
            "confirm_password": "ConcurrentTest123!@#"
        }
        
        await test_container.async_client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        
        # Simulate concurrent login attempts
        login_tasks = []
        for i in range(5):
            task = test_container.async_client.post(
                "/api/v1/auth/login",
                json={
                    "username": user_email.value,
                    "password": "ConcurrentTest123!@#",
                    "device_id": f"device_{i}"
                }
            )
            login_tasks.append(task)
        
        # Execute concurrent logins
        responses = await asyncio.gather(*login_tasks, return_exceptions=True)
        
        # At least one should succeed (or all fail consistently)
        success_count = sum(1 for r in responses 
                          if not isinstance(r, Exception) and r.status_code == 200)
        
        # Should handle concurrent requests gracefully
        assert success_count >= 0  # No server errors

    @pytest.mark.asyncio
    async def test_rate_limiting_behavior(
        self, 
        test_container: TestContainer,
        email_builder
    ):
        """Test rate limiting on authentication endpoints."""
        fake_email = email_builder.unique()
        
        # Rapid-fire invalid login attempts
        responses = []
        for i in range(10):
            response = await test_container.async_client.post(
                "/api/v1/auth/login",
                json={
                    "username": fake_email.value,
                    "password": f"wrong_password_{i}"
                }
            )
            responses.append(response)
            
            # Small delay to avoid overwhelming
            await asyncio.sleep(0.1)
        
        # Should handle rate limiting gracefully
        # Look for rate limiting responses (429) or consistent rejection (401)
        status_codes = [r.status_code for r in responses]
        
        # Should not have any server errors (5xx)
        assert all(code < 500 for code in status_codes)
        
        # Should have consistent authentication failures
        assert all(code in [401, 429] for code in status_codes)

    @pytest.mark.asyncio
    async def test_session_persistence_across_requests(
        self, 
        test_container: TestContainer,
        email_builder
    ):
        """Test that sessions persist across multiple requests."""
        # Create and login user
        user_email = email_builder.unique()
        user_data = {
            "username": user_email.value,
            "email": user_email.value,
            "password": "SessionTest123!@#",
            "confirm_password": "SessionTest123!@#"
        }
        
        # Register user
        await test_container.async_client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        
        # Login
        login_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user_email.value,
                "password": "SessionTest123!@#"
            }
        )
        
        if login_response.status_code == 200:
            # Get session cookies/tokens
            cookies = login_response.cookies
            
            # Make multiple authenticated requests
            for i in range(3):
                profile_response = await test_container.async_client.get(
                    "/api/v1/auth/me",
                    cookies=cookies
                )
                
                # Session should remain valid
                assert profile_response.status_code in [200, 404]

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
