"""
Integration tests for MFA workflows.

Tests complete MFA setup, verification, and management workflows
end-to-end with real dependencies and database interactions.
"""


import pytest

from app.modules.identity.application.commands.authentication import (
    LoginCommand,
    RegisterUserCommand,
)
from app.modules.identity.application.commands.mfa import (
    DisableMfaCommand,
    GenerateBackupCodesCommand,
    SetupMfaCommand,
    VerifyMfaChallengeCommand,
    VerifyMfaSetupCommand,
)
from app.modules.identity.application.queries.mfa import (
    GetMfaDevicesQuery,
    GetMfaStatusQuery,
)
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.exceptions import InvalidMfaCodeError


@pytest.mark.integration
class TestMfaSetupWorkflow:
    """Test MFA setup workflow integration."""

    @pytest.fixture
    async def test_user(self, app_container, faker):
        """Create a test user for MFA testing."""
        register_handler = app_container.get("register_user_command_handler")

        command = RegisterUserCommand(
            email=faker.email(),
            username=faker.user_name(),
            password="TestPassword123!@#",
            first_name=faker.first_name(),
            last_name=faker.last_name(),
            terms_accepted=True,
        )

        result = await register_handler.handle(command)
        return result.user_id

    @pytest.mark.asyncio
    async def test_complete_totp_setup_workflow(self, app_container, test_user):
        """Test complete TOTP MFA setup workflow."""
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        get_status_handler = app_container.get("get_mfa_status_query_handler")
        totp_service = app_container.get("totp_service")

        # Step 1: Setup MFA
        setup_command = SetupMfaCommand(
            user_id=test_user,
            method=MFAMethod.TOTP,
            device_name="Test Authenticator App",
            device_id="test-device-123",
        )

        setup_result = await setup_handler.handle(setup_command)

        assert setup_result.success is True
        assert setup_result.method == MFAMethod.TOTP
        assert setup_result.secret is not None
        assert setup_result.qr_code is not None
        assert len(setup_result.backup_codes) == 10

        # Step 2: Verify MFA setup with correct code
        # Generate a valid TOTP code using the secret
        valid_code = totp_service.generate_code(setup_result.secret)

        verify_command = VerifyMfaSetupCommand(
            user_id=test_user,
            device_id=setup_result.device_id,
            verification_code=valid_code,
        )

        verify_result = await verify_setup_handler.handle(verify_command)

        assert verify_result.success is True
        assert verify_result.mfa_enabled is True

        # Step 3: Verify MFA status is updated
        status_query = GetMfaStatusQuery(user_id=test_user)
        status_result = await get_status_handler.handle(status_query)

        assert status_result.mfa_enabled is True
        assert status_result.device_count == 1
        assert status_result.primary_method == MFAMethod.TOTP
        assert status_result.backup_codes_remaining == 10

    @pytest.mark.asyncio
    async def test_mfa_setup_with_invalid_verification(self, app_container, test_user):
        """Test MFA setup with invalid verification code."""
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")

        # Setup MFA
        setup_command = SetupMfaCommand(
            user_id=test_user, method=MFAMethod.TOTP, device_name="Test App"
        )

        setup_result = await setup_handler.handle(setup_command)

        # Try to verify with invalid code
        verify_command = VerifyMfaSetupCommand(
            user_id=test_user,
            device_id=setup_result.device_id,
            verification_code="000000",  # Invalid code
        )

        with pytest.raises(InvalidMfaCodeError):
            await verify_setup_handler.handle(verify_command)

        # Verify MFA is still not enabled
        get_status_handler = app_container.get("get_mfa_status_query_handler")
        status_query = GetMfaStatusQuery(user_id=test_user)
        status_result = await get_status_handler.handle(status_query)

        assert status_result.mfa_enabled is False

    @pytest.mark.asyncio
    async def test_sms_mfa_setup_workflow(self, app_container, test_user):
        """Test SMS MFA setup workflow."""
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")

        phone_number = "+1-555-123-4567"

        # Setup SMS MFA
        setup_command = SetupMfaCommand(
            user_id=test_user,
            method=MFAMethod.SMS,
            device_name="Test Phone",
            phone_number=phone_number,
        )

        setup_result = await setup_handler.handle(setup_command)

        assert setup_result.success is True
        assert setup_result.method == MFAMethod.SMS
        assert setup_result.verification_sent is True

        # In a real scenario, we would receive the SMS code
        # For testing, we'll use a test code
        test_sms_code = "123456"

        # Mock the SMS service to return our test code
        sms_service = app_container.get("sms_service")
        sms_service.get_last_sent_code = lambda phone: test_sms_code

        verify_command = VerifyMfaSetupCommand(
            user_id=test_user,
            device_id=setup_result.device_id,
            verification_code=test_sms_code,
        )

        verify_result = await verify_setup_handler.handle(verify_command)

        assert verify_result.success is True
        assert verify_result.mfa_enabled is True

    @pytest.mark.asyncio
    async def test_multiple_mfa_devices_setup(self, app_container, test_user):
        """Test setting up multiple MFA devices."""
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        get_devices_handler = app_container.get("get_mfa_devices_query_handler")
        totp_service = app_container.get("totp_service")

        devices_setup = []

        # Setup TOTP device first
        totp_command = SetupMfaCommand(
            user_id=test_user,
            method=MFAMethod.TOTP,
            device_name="Primary Authenticator",
        )

        totp_result = await setup_handler.handle(totp_command)
        totp_code = totp_service.generate_code(totp_result.secret)

        verify_totp = VerifyMfaSetupCommand(
            user_id=test_user,
            device_id=totp_result.device_id,
            verification_code=totp_code,
        )

        await verify_setup_handler.handle(verify_totp)
        devices_setup.append(totp_result.device_id)

        # Setup SMS device as backup
        sms_command = SetupMfaCommand(
            user_id=test_user,
            method=MFAMethod.SMS,
            device_name="Backup Phone",
            phone_number="+1-555-987-6543",
        )

        sms_result = await setup_handler.handle(sms_command)

        # Mock SMS verification
        sms_service = app_container.get("sms_service")
        test_code = "789012"
        sms_service.get_last_sent_code = lambda phone: test_code

        verify_sms = VerifyMfaSetupCommand(
            user_id=test_user,
            device_id=sms_result.device_id,
            verification_code=test_code,
        )

        await verify_setup_handler.handle(verify_sms)
        devices_setup.append(sms_result.device_id)

        # Verify both devices are configured
        devices_query = GetMfaDevicesQuery(user_id=test_user)
        devices_result = await get_devices_handler.handle(devices_query)

        assert devices_result.total_devices == 2
        assert any(d.method == MFAMethod.TOTP for d in devices_result.devices)
        assert any(d.method == MFAMethod.SMS for d in devices_result.devices)
        assert any(d.is_primary for d in devices_result.devices)


@pytest.mark.integration
class TestMfaLoginWorkflow:
    """Test MFA login workflow integration."""

    @pytest.fixture
    async def user_with_mfa(self, app_container, faker):
        """Create a user with MFA already setup."""
        # Register user
        register_handler = app_container.get("register_user_command_handler")
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        totp_service = app_container.get("totp_service")

        email = faker.email()
        password = "TestPassword123!@#"

        register_command = RegisterUserCommand(
            email=email,
            username=faker.user_name(),
            password=password,
            first_name=faker.first_name(),
            last_name=faker.last_name(),
            terms_accepted=True,
        )

        register_result = await register_handler.handle(register_command)
        user_id = register_result.user_id

        # Setup MFA
        setup_command = SetupMfaCommand(
            user_id=user_id, method=MFAMethod.TOTP, device_name="Test Authenticator"
        )

        setup_result = await setup_handler.handle(setup_command)
        totp_secret = setup_result.secret

        # Verify MFA setup
        totp_code = totp_service.generate_code(totp_secret)
        verify_command = VerifyMfaSetupCommand(
            user_id=user_id,
            device_id=setup_result.device_id,
            verification_code=totp_code,
        )

        await verify_setup_handler.handle(verify_command)

        return {
            "user_id": user_id,
            "email": email,
            "password": password,
            "totp_secret": totp_secret,
            "device_id": setup_result.device_id,
            "backup_codes": setup_result.backup_codes,
        }

    @pytest.mark.asyncio
    async def test_login_with_mfa_challenge(self, app_container, user_with_mfa):
        """Test login workflow with MFA challenge."""
        login_handler = app_container.get("login_command_handler")
        verify_mfa_handler = app_container.get("verify_mfa_challenge_command_handler")
        totp_service = app_container.get("totp_service")

        # Step 1: Initial login (should require MFA)
        login_command = LoginCommand(
            email=user_with_mfa["email"],
            password=user_with_mfa["password"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
        )

        login_result = await login_handler.handle(login_command)

        assert login_result.mfa_required is True
        assert login_result.mfa_challenge_token is not None
        assert login_result.access_token is None  # No access token until MFA completed

        # Step 2: Complete MFA challenge
        totp_code = totp_service.generate_code(user_with_mfa["totp_secret"])

        mfa_command = VerifyMfaChallengeCommand(
            user_id=user_with_mfa["user_id"],
            session_id=login_result.session_id,
            verification_code=totp_code,
            device_id=user_with_mfa["device_id"],
        )

        mfa_result = await verify_mfa_handler.handle(mfa_command)

        assert mfa_result.success is True
        assert mfa_result.access_token is not None
        assert mfa_result.mfa_completed is True

    @pytest.mark.asyncio
    async def test_login_with_backup_code(self, app_container, user_with_mfa):
        """Test login using MFA backup code."""
        login_handler = app_container.get("login_command_handler")
        verify_mfa_handler = app_container.get("verify_mfa_challenge_command_handler")

        # Initial login
        login_command = LoginCommand(
            email=user_with_mfa["email"],
            password=user_with_mfa["password"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
        )

        login_result = await login_handler.handle(login_command)

        # Use backup code instead of TOTP
        backup_code = user_with_mfa["backup_codes"][0]

        mfa_command = VerifyMfaChallengeCommand(
            user_id=user_with_mfa["user_id"],
            session_id=login_result.session_id,
            backup_code=backup_code,
        )

        mfa_result = await verify_mfa_handler.handle(mfa_command)

        assert mfa_result.success is True
        assert mfa_result.backup_code_used is True
        assert mfa_result.access_token is not None

    @pytest.mark.asyncio
    async def test_login_with_trusted_device(self, app_container, user_with_mfa):
        """Test login with trusted device bypassing MFA."""
        login_handler = app_container.get("login_command_handler")
        device_service = app_container.get("device_service")

        trusted_device_id = "trusted-device-123"

        # Mark device as trusted
        await device_service.trust_device(
            user_id=user_with_mfa["user_id"],
            device_id=trusted_device_id,
            device_fingerprint="trusted_fingerprint",
        )

        # Login with trusted device
        login_command = LoginCommand(
            email=user_with_mfa["email"],
            password=user_with_mfa["password"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
            device_id=trusted_device_id,
        )

        login_result = await login_handler.handle(login_command)

        # Should bypass MFA for trusted device
        assert login_result.mfa_required is False
        assert login_result.access_token is not None
        assert login_result.trusted_device_used is True

    @pytest.mark.asyncio
    async def test_mfa_failure_lockout(self, app_container, user_with_mfa):
        """Test MFA device lockout after multiple failures."""
        login_handler = app_container.get("login_command_handler")
        verify_mfa_handler = app_container.get("verify_mfa_challenge_command_handler")

        # Initial login
        login_command = LoginCommand(
            email=user_with_mfa["email"],
            password=user_with_mfa["password"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
        )

        login_result = await login_handler.handle(login_command)

        # Try invalid MFA codes multiple times
        for _ in range(5):  # Assuming 5 failures trigger lockout
            mfa_command = VerifyMfaChallengeCommand(
                user_id=user_with_mfa["user_id"],
                session_id=login_result.session_id,
                verification_code="000000",  # Wrong code
                device_id=user_with_mfa["device_id"],
            )

            try:
                await verify_mfa_handler.handle(mfa_command)
            except InvalidMfaCodeError:
                pass  # Expected failure

        # Next attempt should indicate device is locked
        final_mfa_command = VerifyMfaChallengeCommand(
            user_id=user_with_mfa["user_id"],
            session_id=login_result.session_id,
            verification_code="000000",
            device_id=user_with_mfa["device_id"],
        )

        with pytest.raises(ValueError, match="locked"):
            await verify_mfa_handler.handle(final_mfa_command)


@pytest.mark.integration
class TestMfaManagementWorkflow:
    """Test MFA management workflow integration."""

    @pytest.fixture
    async def user_with_mfa(self, app_container, faker):
        """Create a user with MFA setup for management testing."""
        # This is the same fixture as above, but including it for clarity
        register_handler = app_container.get("register_user_command_handler")
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        totp_service = app_container.get("totp_service")

        email = faker.email()
        password = "TestPassword123!@#"

        register_command = RegisterUserCommand(
            email=email,
            username=faker.user_name(),
            password=password,
            first_name=faker.first_name(),
            last_name=faker.last_name(),
            terms_accepted=True,
        )

        register_result = await register_handler.handle(register_command)
        user_id = register_result.user_id

        # Setup MFA
        setup_command = SetupMfaCommand(
            user_id=user_id, method=MFAMethod.TOTP, device_name="Test Authenticator"
        )

        setup_result = await setup_handler.handle(setup_command)

        # Verify MFA setup
        totp_code = totp_service.generate_code(setup_result.secret)
        verify_command = VerifyMfaSetupCommand(
            user_id=user_id,
            device_id=setup_result.device_id,
            verification_code=totp_code,
        )

        await verify_setup_handler.handle(verify_command)

        return {
            "user_id": user_id,
            "email": email,
            "password": password,
            "totp_secret": setup_result.secret,
            "device_id": setup_result.device_id,
            "backup_codes": setup_result.backup_codes,
        }

    @pytest.mark.asyncio
    async def test_generate_new_backup_codes(self, app_container, user_with_mfa):
        """Test generating new backup codes."""
        generate_codes_handler = app_container.get(
            "generate_backup_codes_command_handler"
        )
        get_status_handler = app_container.get("get_mfa_status_query_handler")

        # Generate new backup codes
        generate_command = GenerateBackupCodesCommand(
            user_id=user_with_mfa["user_id"], invalidate_existing=True
        )

        generate_result = await generate_codes_handler.handle(generate_command)

        assert generate_result.success is True
        assert len(generate_result.backup_codes) == 10
        assert generate_result.codes_generated == 10

        # Verify new codes are different from original
        original_codes = set(user_with_mfa["backup_codes"])
        new_codes = set(generate_result.backup_codes)
        assert original_codes != new_codes

        # Verify status shows full backup codes
        status_query = GetMfaStatusQuery(user_id=user_with_mfa["user_id"])
        status_result = await get_status_handler.handle(status_query)

        assert status_result.backup_codes_remaining == 10

    @pytest.mark.asyncio
    async def test_disable_mfa_workflow(self, app_container, user_with_mfa):
        """Test disabling MFA completely."""
        disable_handler = app_container.get("disable_mfa_command_handler")
        get_status_handler = app_container.get("get_mfa_status_query_handler")

        # Disable MFA with correct password
        disable_command = DisableMfaCommand(
            user_id=user_with_mfa["user_id"],
            password=user_with_mfa["password"],
            reason="Testing disable workflow",
        )

        disable_result = await disable_handler.handle(disable_command)

        assert disable_result.success is True
        assert disable_result.mfa_disabled is True

        # Verify MFA is disabled
        status_query = GetMfaStatusQuery(user_id=user_with_mfa["user_id"])
        status_result = await get_status_handler.handle(status_query)

        assert status_result.mfa_enabled is False
        assert status_result.device_count == 0
        assert status_result.backup_codes_remaining == 0

    @pytest.mark.asyncio
    async def test_disable_mfa_wrong_password(self, app_container, user_with_mfa):
        """Test disabling MFA with wrong password."""
        disable_handler = app_container.get("disable_mfa_command_handler")

        # Try to disable MFA with wrong password
        disable_command = DisableMfaCommand(
            user_id=user_with_mfa["user_id"],
            password="WrongPassword123!",
            reason="Testing wrong password",
        )

        with pytest.raises(ValueError, match="password"):
            await disable_handler.handle(disable_command)

        # Verify MFA is still enabled
        get_status_handler = app_container.get("get_mfa_status_query_handler")
        status_query = GetMfaStatusQuery(user_id=user_with_mfa["user_id"])
        status_result = await get_status_handler.handle(status_query)

        assert status_result.mfa_enabled is True

    @pytest.mark.asyncio
    async def test_re_enable_mfa_after_disable(self, app_container, user_with_mfa):
        """Test re-enabling MFA after it was disabled."""
        disable_handler = app_container.get("disable_mfa_command_handler")
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        totp_service = app_container.get("totp_service")

        # First disable MFA
        disable_command = DisableMfaCommand(
            user_id=user_with_mfa["user_id"], password=user_with_mfa["password"]
        )

        await disable_handler.handle(disable_command)

        # Re-setup MFA with new device
        setup_command = SetupMfaCommand(
            user_id=user_with_mfa["user_id"],
            method=MFAMethod.TOTP,
            device_name="New Authenticator",
        )

        setup_result = await setup_handler.handle(setup_command)

        # Verify setup
        totp_code = totp_service.generate_code(setup_result.secret)
        verify_command = VerifyMfaSetupCommand(
            user_id=user_with_mfa["user_id"],
            device_id=setup_result.device_id,
            verification_code=totp_code,
        )

        verify_result = await verify_setup_handler.handle(verify_command)

        assert verify_result.success is True
        assert verify_result.mfa_enabled is True

    @pytest.mark.asyncio
    async def test_mfa_device_management(self, app_container, user_with_mfa):
        """Test adding and removing MFA devices."""
        setup_handler = app_container.get("setup_mfa_command_handler")
        verify_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        get_devices_handler = app_container.get("get_mfa_devices_query_handler")
        remove_device_handler = app_container.get("remove_mfa_device_command_handler")

        # Add a second device
        setup_command = SetupMfaCommand(
            user_id=user_with_mfa["user_id"],
            method=MFAMethod.SMS,
            device_name="Backup SMS",
            phone_number="+1-555-123-4567",
        )

        setup_result = await setup_handler.handle(setup_command)

        # Mock SMS verification
        sms_service = app_container.get("sms_service")
        test_code = "654321"
        sms_service.get_last_sent_code = lambda phone: test_code

        verify_command = VerifyMfaSetupCommand(
            user_id=user_with_mfa["user_id"],
            device_id=setup_result.device_id,
            verification_code=test_code,
        )

        await verify_setup_handler.handle(verify_command)

        # Verify we have 2 devices
        devices_query = GetMfaDevicesQuery(user_id=user_with_mfa["user_id"])
        devices_result = await get_devices_handler.handle(devices_query)

        assert devices_result.total_devices == 2

        # Remove the SMS device
        remove_command = RemoveMfaDeviceCommand(
            user_id=user_with_mfa["user_id"],
            device_id=setup_result.device_id,
            password=user_with_mfa["password"],
        )

        await remove_device_handler.handle(remove_command)

        # Verify we're back to 1 device
        devices_result_after = await get_devices_handler.handle(devices_query)
        assert devices_result_after.total_devices == 1
        assert devices_result_after.devices[0].method == MFAMethod.TOTP
