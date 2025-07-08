"""Test user login mutation."""
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient

from app.modules.identity.domain.entities import User


class TestUserLogin:
    """Test cases for user login mutation."""

    @pytest.mark.asyncio
    async def test_login_success(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
        mock_user_service,
    ):
        """Test successful user login."""
        # Arrange
        mock_user_service.authenticate_user.return_value = (
            test_user,
            "mock_access_token",
        )

        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "login")
        assert result["data"]["login"]["user"]["username"] == test_user.username.value
        assert result["data"]["login"]["user"]["email"] == test_user.email.value
        assert result["data"]["login"]["token"]["accessToken"] is not None
        assert result["data"]["login"]["token"]["tokenType"] == "Bearer"

    @pytest.mark.asyncio
    async def test_login_with_email(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test login using email instead of username."""
        # Arrange
        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.email.value,
                    "password": "TestPassword123!",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "login")
        assert result["data"]["login"]["user"]["email"] == test_user.email.value

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test login with invalid credentials."""
        # Arrange
        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": "nonexistent",
                    "password": "wrongpassword",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Invalid credentials")

    @pytest.mark.asyncio
    async def test_login_inactive_user(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test login with inactive user account."""
        # Arrange
        test_user.is_active = False

        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Account is inactive")

    @pytest.mark.asyncio
    async def test_login_unverified_email(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test login with unverified email address."""
        # Arrange
        test_user.email_verified = False

        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Email not verified")

    @pytest.mark.asyncio
    async def test_login_locked_account(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test login with locked account after multiple failed attempts."""
        # Arrange
        test_user.failed_login_attempts = 5
        test_user.lockout_until = datetime.utcnow() + timedelta(minutes=30)

        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Account is locked")

    @pytest.mark.asyncio
    async def test_login_creates_audit_entry(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
        mock_audit_service,
    ):
        """Test that login creates an audit entry."""
        # Arrange
        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "login")
        mock_audit_service.log_event.assert_called_once()

        # Verify audit entry details
        call_args = mock_audit_service.log_event.call_args[1]
        assert call_args["action"] == "user.login"
        assert call_args["resource_type"] == "user"
        assert call_args["actor_id"] == str(test_user.id.value)

    @pytest.mark.asyncio
    async def test_login_with_remember_me(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test login with remember me option."""
        # Arrange
        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                    "rememberMe": True,
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "login")
        # Check that token expiry is extended
        assert result["data"]["login"]["token"]["expiresIn"] > 3600  # More than 1 hour

    @pytest.mark.asyncio
    async def test_login_with_device_info(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
        mock_audit_service,
    ):
        """Test login with device information."""
        # Arrange
        device_info = {
            "deviceId": "device123",
            "deviceName": "iPhone 12",
            "deviceType": "mobile",
        }

        request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                    "deviceInfo": device_info,
                }
            },
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "login")

        # Verify device info is logged
        call_args = mock_audit_service.log_event.call_args[1]
        assert call_args["metadata"]["device_id"] == device_info["deviceId"]
        assert call_args["metadata"]["device_name"] == device_info["deviceName"]
