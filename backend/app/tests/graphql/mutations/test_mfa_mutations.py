"""Test Multi-Factor Authentication (MFA) mutations."""

import pyotp
import pytest
from httpx import AsyncClient


class TestMFAMutations:
    """Test cases for MFA-related mutations."""

    @pytest.mark.asyncio
    async def test_enable_mfa(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test enabling MFA for a user."""
        # Arrange
        mutation = """
        mutation EnableMFA {
            enableMFA {
                secret
                qrCode
                backupCodes
            }
        }
        """

        request = make_graphql_request(query=mutation)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "enableMFA")
        mfa_data = result["data"]["enableMFA"]
        assert mfa_data["secret"] is not None
        assert mfa_data["qrCode"] is not None
        assert isinstance(mfa_data["backupCodes"], list)
        assert len(mfa_data["backupCodes"]) >= 8

    @pytest.mark.asyncio
    async def test_verify_mfa_setup(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test verifying MFA setup with TOTP code."""
        # Arrange
        # First enable MFA to get secret
        enable_mutation = """
        mutation EnableMFA {
            enableMFA {
                secret
            }
        }
        """

        enable_request = make_graphql_request(query=enable_mutation)
        enable_response = await authenticated_graphql_client.post(
            "", json=enable_request
        )
        enable_result = enable_response.json()

        secret = enable_result["data"]["enableMFA"]["secret"]

        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Verify MFA setup
        verify_mutation = """
        mutation VerifyMFASetup($code: String!) {
            verifyMFASetup(code: $code) {
                success
                message
            }
        }
        """

        verify_request = make_graphql_request(
            query=verify_mutation, variables={"code": code}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=verify_request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "verifyMFASetup")
        assert result["data"]["verifyMFASetup"]["success"] is True

    @pytest.mark.asyncio
    async def test_disable_mfa(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test disabling MFA."""
        # Arrange
        mutation = """
        mutation DisableMFA($password: String!) {
            disableMFA(password: $password) {
                success
                message
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"password": "TestPassword123!"}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "disableMFA")
        assert result["data"]["disableMFA"]["success"] is True

    @pytest.mark.asyncio
    async def test_regenerate_backup_codes(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test regenerating MFA backup codes."""
        # Arrange
        mutation = """
        mutation RegenerateBackupCodes($password: String!) {
            regenerateMFABackupCodes(password: $password) {
                backupCodes
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"password": "TestPassword123!"}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "regenerateMFABackupCodes")
        backup_codes = result["data"]["regenerateMFABackupCodes"]["backupCodes"]
        assert isinstance(backup_codes, list)
        assert len(backup_codes) >= 8

        # Verify codes are unique
        assert len(backup_codes) == len(set(backup_codes))

    @pytest.mark.asyncio
    async def test_login_with_mfa(
        self,
        graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test login flow with MFA enabled."""
        # Arrange
        # First step: Initial login
        login_mutation = """
        mutation LoginWithMFA($input: LoginInput!) {
            login(input: $input) {
                requiresMFA
                mfaToken
                user {
                    id
                }
                token {
                    accessToken
                }
            }
        }
        """

        login_request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        login_response = await graphql_client.post("", json=login_request)
        login_result = login_response.json()

        assert_graphql_success(login_result, "login")
        assert login_result["data"]["login"]["requiresMFA"] is True
        assert login_result["data"]["login"]["mfaToken"] is not None
        assert login_result["data"]["login"]["token"] is None  # No access token yet

        mfa_token = login_result["data"]["login"]["mfaToken"]

        # Second step: Verify MFA
        verify_mutation = """
        mutation VerifyMFALogin($mfaToken: String!, $code: String!) {
            verifyMFALogin(mfaToken: $mfaToken, code: $code) {
                user {
                    id
                    username
                }
                token {
                    accessToken
                    refreshToken
                }
            }
        }
        """

        # Generate valid TOTP code (in real test would use actual secret)
        code = "123456"

        verify_request = make_graphql_request(
            query=verify_mutation, variables={"mfaToken": mfa_token, "code": code}
        )

        # Act
        response = await graphql_client.post("", json=verify_request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "verifyMFALogin")
        assert result["data"]["verifyMFALogin"]["token"]["accessToken"] is not None

    @pytest.mark.asyncio
    async def test_login_with_backup_code(
        self,
        graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test login using MFA backup code."""
        # Arrange
        mutation = """
        mutation LoginWithBackupCode($mfaToken: String!, $backupCode: String!) {
            verifyMFALoginWithBackupCode(mfaToken: $mfaToken, backupCode: $backupCode) {
                user {
                    id
                    username
                }
                token {
                    accessToken
                }
                remainingBackupCodes
            }
        }
        """

        request = make_graphql_request(
            query=mutation,
            variables={"mfaToken": "valid_mfa_token", "backupCode": "BACKUP-CODE-123"},
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "verifyMFALoginWithBackupCode")
        assert (
            result["data"]["verifyMFALoginWithBackupCode"]["token"]["accessToken"]
            is not None
        )
        assert isinstance(
            result["data"]["verifyMFALoginWithBackupCode"]["remainingBackupCodes"], int
        )

    @pytest.mark.asyncio
    async def test_add_trusted_device(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test adding a trusted device for MFA."""
        # Arrange
        mutation = """
        mutation AddTrustedDevice($deviceInfo: DeviceInfoInput!) {
            addTrustedDevice(deviceInfo: $deviceInfo) {
                deviceId
                deviceName
                trustToken
                expiresAt
            }
        }
        """

        request = make_graphql_request(
            query=mutation,
            variables={
                "deviceInfo": {
                    "deviceName": "My Laptop",
                    "deviceType": "desktop",
                    "browserInfo": "Chrome 120.0",
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "addTrustedDevice")
        device_data = result["data"]["addTrustedDevice"]
        assert device_data["deviceId"] is not None
        assert device_data["deviceName"] == "My Laptop"
        assert device_data["trustToken"] is not None

    @pytest.mark.asyncio
    async def test_list_trusted_devices(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test listing user's trusted devices."""
        # Arrange
        query = """
        query ListTrustedDevices {
            me {
                trustedDevices {
                    deviceId
                    deviceName
                    deviceType
                    lastUsed
                    createdAt
                }
            }
        }
        """

        request = make_graphql_request(query=query)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "me")
        devices = result["data"]["me"]["trustedDevices"]
        assert isinstance(devices, list)

    @pytest.mark.asyncio
    async def test_remove_trusted_device(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test removing a trusted device."""
        # Arrange
        mutation = """
        mutation RemoveTrustedDevice($deviceId: String!) {
            removeTrustedDevice(deviceId: $deviceId) {
                success
                message
            }
        }
        """

        request = make_graphql_request(
            query=mutation, variables={"deviceId": "device123"}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "removeTrustedDevice")
        assert result["data"]["removeTrustedDevice"]["success"] is True

    @pytest.mark.asyncio
    async def test_mfa_recovery_flow(
        self,
        graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
        mock_notification_service,
    ):
        """Test MFA recovery flow when user loses access."""
        # Arrange
        mutation = """
        mutation RequestMFARecovery($email: String!) {
            requestMFARecovery(email: $email) {
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
        assert_graphql_success(result, "requestMFARecovery")
        assert result["data"]["requestMFARecovery"]["success"] is True

        # Verify recovery email was sent
        mock_notification_service.send_email.assert_called_once()
        email_args = mock_notification_service.send_email.call_args[1]
        assert email_args["to"] == test_user.email.value
        assert "mfa recovery" in email_args["subject"].lower()
