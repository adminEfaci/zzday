"""Test authentication flow mutations."""

import pytest
from httpx import AsyncClient


class TestAuthenticationFlow:
    """Test cases for authentication flow including refresh tokens, logout, etc."""

    @pytest.mark.asyncio
    async def test_refresh_token(
        self,
        graphql_client: AsyncClient,
        test_user,
        jwt_handler,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test refreshing access token using refresh token."""
        # Arrange
        refresh_token = jwt_handler.create_refresh_token(
            {"sub": str(test_user.id.value)}
        )

        mutation = """
        mutation RefreshToken($refreshToken: String!) {
            refreshToken(refreshToken: $refreshToken) {
                accessToken
                refreshToken
                tokenType
                expiresIn
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"refreshToken": refresh_token}
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "refreshToken")
        token_data = result["data"]["refreshToken"]
        assert token_data["accessToken"] is not None
        assert token_data["refreshToken"] is not None
        assert token_data["tokenType"] == "Bearer"
        assert token_data["expiresIn"] > 0

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(
        self, graphql_client: AsyncClient, make_graphql_request, assert_graphql_error
    ):
        """Test refreshing with invalid refresh token."""
        # Arrange
        mutation = """
        mutation RefreshToken($refreshToken: String!) {
            refreshToken(refreshToken: $refreshToken) {
                accessToken
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"refreshToken": "invalid_token"}
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Invalid refresh token")

    @pytest.mark.asyncio
    async def test_logout(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
        mock_audit_service,
    ):
        """Test user logout."""
        # Arrange
        mutation = """
        mutation Logout {
            logout {
                success
                message
            }
        }
        """

        request = make_graphql_request(query=mutation)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "logout")
        assert result["data"]["logout"]["success"] is True
        assert result["data"]["logout"]["message"] == "Logged out successfully"

        # Verify audit log
        mock_audit_service.log_event.assert_called_once()
        call_args = mock_audit_service.log_event.call_args[1]
        assert call_args["action"] == "user.logout"

    @pytest.mark.asyncio
    async def test_logout_all_sessions(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test logging out from all sessions."""
        # Arrange
        mutation = """
        mutation LogoutAllSessions {
            logoutAllSessions {
                success
                message
                sessionsTerminated
            }
        }
        """

        request = make_graphql_request(query=mutation)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "logoutAllSessions")
        assert result["data"]["logoutAllSessions"]["success"] is True
        assert result["data"]["logoutAllSessions"]["sessionsTerminated"] >= 1

    @pytest.mark.asyncio
    async def test_request_password_reset(
        self,
        graphql_client: AsyncClient,
        test_user,
        make_graphql_request,
        assert_graphql_success,
        mock_notification_service,
    ):
        """Test requesting password reset."""
        # Arrange
        mutation = """
        mutation RequestPasswordReset($email: String!) {
            requestPasswordReset(email: $email) {
                success
                message
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"email": test_user.email.value}
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "requestPasswordReset")
        assert result["data"]["requestPasswordReset"]["success"] is True

        # Verify email was sent
        mock_notification_service.send_email.assert_called_once()
        email_args = mock_notification_service.send_email.call_args[1]
        assert email_args["to"] == test_user.email.value
        assert "password reset" in email_args["subject"].lower()

    @pytest.mark.asyncio
    async def test_reset_password(
        self,
        graphql_client: AsyncClient,
        test_user,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test resetting password with token."""
        # Arrange
        reset_token = "valid_reset_token"

        mutation = """
        mutation ResetPassword($token: String!, $newPassword: String!) {
            resetPassword(token: $token, newPassword: $newPassword) {
                success
                message
            }
        }
        """

        request = make_graphql_request(
            query=mutation,
            variables={"token": reset_token, "newPassword": "NewSecurePassword123!"},
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "resetPassword")
        assert result["data"]["resetPassword"]["success"] is True

    @pytest.mark.asyncio
    async def test_change_password(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test changing password for authenticated user."""
        # Arrange
        mutation = """
        mutation ChangePassword($currentPassword: String!, $newPassword: String!) {
            changePassword(currentPassword: $currentPassword, newPassword: $newPassword) {
                success
                message
            }
        }
        """

        request = make_graphql_request(
            query=mutation,
            variables={
                "currentPassword": "TestPassword123!",
                "newPassword": "NewSecurePassword123!",
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "changePassword")
        assert result["data"]["changePassword"]["success"] is True

    @pytest.mark.asyncio
    async def test_verify_email(
        self, graphql_client: AsyncClient, make_graphql_request, assert_graphql_success
    ):
        """Test email verification."""
        # Arrange
        verification_token = "valid_verification_token"

        mutation = """
        mutation VerifyEmail($token: String!) {
            verifyEmail(token: $token) {
                success
                message
                user {
                    id
                    email
                    emailVerified
                }
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"token": verification_token}
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "verifyEmail")
        assert result["data"]["verifyEmail"]["success"] is True
        assert result["data"]["verifyEmail"]["user"]["emailVerified"] is True

    @pytest.mark.asyncio
    async def test_resend_verification_email(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
        mock_notification_service,
    ):
        """Test resending verification email."""
        # Arrange
        mutation = """
        mutation ResendVerificationEmail {
            resendVerificationEmail {
                success
                message
            }
        }
        """

        request = make_graphql_request(query=mutation)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "resendVerificationEmail")
        assert result["data"]["resendVerificationEmail"]["success"] is True

        # Verify email was sent
        mock_notification_service.send_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_token(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test revoking a specific token."""
        # Arrange
        token_id = "token_123"

        mutation = """
        mutation RevokeToken($tokenId: String!) {
            revokeToken(tokenId: $tokenId) {
                success
                message
            }
        }
        """

        request = make_graphql_request(query=mutation, variables={"tokenId": token_id})

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "revokeToken")
        assert result["data"]["revokeToken"]["success"] is True
