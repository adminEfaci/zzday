"""
Test cases for MFA command and query handlers.

Tests all MFA-related handlers including setup, verification,
backup codes, and device management.
"""

import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.mfa import (
    DisableMfaCommand,
    DisableMfaCommandHandler,
    GenerateBackupCodesCommand,
    GenerateBackupCodesCommandHandler,
    SetupMfaCommand,
    SetupMfaCommandHandler,
    VerifyMfaChallengeCommand,
    VerifyMfaChallengeCommandHandler,
    VerifyMfaSetupCommand,
    VerifyMfaSetupCommandHandler,
)
from app.modules.identity.application.queries.mfa import (
    GetMfaDevicesQuery,
    GetMfaDevicesQueryHandler,
    GetMfaStatusQuery,
    GetMfaStatusQueryHandler,
)
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities import MfaDevice
from app.modules.identity.domain.enums import MfaDeviceStatus, MFAMethod
from app.modules.identity.domain.exceptions import (
    InvalidMfaCodeError,
    MfaAlreadySetupError,
    MfaNotSetupError,
    UserNotFoundError,
)


class TestSetupMfaCommandHandler:
    """Test MFA setup command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_mfa_service = Mock()
        mock_security_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return SetupMfaCommandHandler(
            user_repository=mock_user_repo,
            mfa_service=mock_mfa_service,
            security_service=mock_security_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_totp_setup(self, handler):
        """Test successful TOTP MFA setup."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = False
        user.setup_mfa_device = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.mfa_service.generate_totp_secret = Mock(return_value="JBSWY3DPEHPK3PXP")
        handler.mfa_service.generate_qr_code = Mock(
            return_value="data:image/png;base64,..."
        )
        handler.security_service.validate_device_trust = AsyncMock(return_value=True)
        handler.user_repository.save = AsyncMock()

        command = SetupMfaCommand(
            user_id=user_id,
            method=MFAMethod.TOTP,
            device_name="iPhone Authenticator",
            device_id="device-123",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.method == MFAMethod.TOTP
        assert result.secret == "JBSWY3DPEHPK3PXP"
        assert result.qr_code is not None
        assert result.backup_codes is not None
        assert len(result.backup_codes) == 10
        user.setup_mfa_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_mfa_user_not_found(self, handler):
        """Test MFA setup when user not found."""
        # Arrange
        handler.user_repository.find_by_id = AsyncMock(return_value=None)

        command = SetupMfaCommand(
            user_id=str(uuid4()), method=MFAMethod.TOTP, device_name="Test Device"
        )

        # Act & Assert
        with pytest.raises(UserNotFoundError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_setup_mfa_already_enabled(self, handler):
        """Test MFA setup when already enabled."""
        # Arrange
        user = Mock(spec=User)
        user.mfa_enabled = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)

        command = SetupMfaCommand(
            user_id=str(uuid4()), method=MFAMethod.TOTP, device_name="Test Device"
        )

        # Act & Assert
        with pytest.raises(MfaAlreadySetupError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_setup_sms_mfa(self, handler):
        """Test SMS MFA setup."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = False
        user.profile.phone_number = "+1-555-123-4567"
        user.setup_mfa_device = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.mfa_service.send_sms_verification = AsyncMock(return_value="123456")
        handler.security_service.validate_device_trust = AsyncMock(return_value=True)
        handler.user_repository.save = AsyncMock()

        command = SetupMfaCommand(
            user_id=user_id,
            method=MFAMethod.SMS,
            device_name="Phone SMS",
            phone_number="+1-555-123-4567",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.method == MFAMethod.SMS
        assert result.verification_sent is True
        handler.mfa_service.send_sms_verification.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_hardware_key_mfa(self, handler):
        """Test hardware key MFA setup."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = False
        user.setup_mfa_device = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.mfa_service.register_hardware_key = AsyncMock(
            return_value={"challenge": "challenge_data", "key_id": "hw_key_123"}
        )
        handler.user_repository.save = AsyncMock()

        command = SetupMfaCommand(
            user_id=user_id,
            method=MFAMethod.HARDWARE_KEY,
            device_name="YubiKey 5",
            hardware_key_data={"public_key": "key_data"},
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.method == MFAMethod.HARDWARE_KEY
        assert result.challenge is not None
        handler.mfa_service.register_hardware_key.assert_called_once()


class TestVerifyMfaSetupCommandHandler:
    """Test MFA setup verification command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_mfa_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return VerifyMfaSetupCommandHandler(
            user_repository=mock_user_repo,
            mfa_service=mock_mfa_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_totp_verification(self, handler):
        """Test successful TOTP setup verification."""
        # Arrange
        user_id = str(uuid4())
        device_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.confirm_mfa_setup = Mock()

        mfa_device = Mock(spec=MfaDevice)
        mfa_device.id = device_id
        mfa_device.method = MFAMethod.TOTP
        mfa_device.secret = "JBSWY3DPEHPK3PXP"
        mfa_device.status = MfaDeviceStatus.PENDING

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.get_mfa_device = AsyncMock(return_value=mfa_device)
        handler.mfa_service.verify_totp_code = Mock(return_value=True)
        handler.user_repository.save = AsyncMock()

        command = VerifyMfaSetupCommand(
            user_id=user_id, device_id=device_id, verification_code="123456"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.mfa_enabled is True
        user.confirm_mfa_setup.assert_called_once()
        handler.mfa_service.verify_totp_code.assert_called_once_with(
            "JBSWY3DPEHPK3PXP", "123456"
        )

    @pytest.mark.asyncio
    async def test_verify_setup_invalid_code(self, handler):
        """Test MFA setup verification with invalid code."""
        # Arrange
        user = Mock(spec=User)
        mfa_device = Mock(spec=MfaDevice)
        mfa_device.method = MFAMethod.TOTP
        mfa_device.record_failed_attempt = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.get_mfa_device = AsyncMock(return_value=mfa_device)
        handler.mfa_service.verify_totp_code = Mock(return_value=False)
        handler.user_repository.save = AsyncMock()

        command = VerifyMfaSetupCommand(
            user_id=str(uuid4()), device_id=str(uuid4()), verification_code="wrong_code"
        )

        # Act & Assert
        with pytest.raises(InvalidMfaCodeError):
            await handler.handle(command)

        mfa_device.record_failed_attempt.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_sms_setup(self, handler):
        """Test SMS MFA setup verification."""
        # Arrange
        user_id = str(uuid4())
        device_id = str(uuid4())

        user = Mock(spec=User)
        user.confirm_mfa_setup = Mock()

        mfa_device = Mock(spec=MfaDevice)
        mfa_device.method = MFAMethod.SMS
        mfa_device.status = MfaDeviceStatus.PENDING

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.get_mfa_device = AsyncMock(return_value=mfa_device)
        handler.mfa_service.verify_sms_code = AsyncMock(return_value=True)
        handler.user_repository.save = AsyncMock()

        command = VerifyMfaSetupCommand(
            user_id=user_id, device_id=device_id, verification_code="123456"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.mfa_enabled is True
        handler.mfa_service.verify_sms_code.assert_called_once()


class TestVerifyMfaChallengeCommandHandler:
    """Test MFA challenge verification command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_session_repo = Mock()
        mock_mfa_service = Mock()
        mock_token_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return VerifyMfaChallengeCommandHandler(
            user_repository=mock_user_repo,
            session_repository=mock_session_repo,
            mfa_service=mock_mfa_service,
            token_service=mock_token_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_mfa_challenge_verification(self, handler):
        """Test successful MFA challenge verification."""
        # Arrange
        user_id = str(uuid4())
        session_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = True
        user.complete_mfa_challenge = Mock()

        session = Mock()
        session.id = session_id
        session.user_id = user_id
        session.requires_mfa = True
        session.complete_mfa = Mock()

        mfa_device = Mock(spec=MfaDevice)
        mfa_device.method = MFAMethod.TOTP
        mfa_device.secret = "JBSWY3DPEHPK3PXP"
        mfa_device.is_active = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.get_primary_mfa_device = AsyncMock(
            return_value=mfa_device
        )
        handler.mfa_service.verify_totp_code = Mock(return_value=True)
        handler.token_service.generate_access_token = Mock(
            return_value="new_access_token"
        )
        handler.session_repository.save = AsyncMock()

        command = VerifyMfaChallengeCommand(
            user_id=user_id,
            session_id=session_id,
            verification_code="123456",
            device_id=mfa_device.id,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.access_token == "new_access_token"
        assert result.mfa_completed is True
        user.complete_mfa_challenge.assert_called_once()
        session.complete_mfa.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_mfa_challenge_with_backup_code(self, handler):
        """Test MFA challenge verification with backup code."""
        # Arrange
        user_id = str(uuid4())
        backup_code = "1234-5678"

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = True
        user.use_backup_code = Mock(return_value=True)
        user.complete_mfa_challenge = Mock()

        session = Mock()
        session.complete_mfa = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.token_service.generate_access_token = Mock(
            return_value="backup_access_token"
        )
        handler.session_repository.save = AsyncMock()
        handler.user_repository.save = AsyncMock()

        command = VerifyMfaChallengeCommand(
            user_id=user_id, session_id=str(uuid4()), backup_code=backup_code
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.backup_code_used is True
        user.use_backup_code.assert_called_once_with(backup_code)

    @pytest.mark.asyncio
    async def test_verify_mfa_challenge_invalid_code(self, handler):
        """Test MFA challenge verification with invalid code."""
        # Arrange
        user = Mock(spec=User)
        user.mfa_enabled = True
        user.record_failed_mfa_attempt = Mock()

        session = Mock()
        session.requires_mfa = True

        mfa_device = Mock(spec=MfaDevice)
        mfa_device.method = MFAMethod.TOTP
        mfa_device.record_failed_attempt = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.get_primary_mfa_device = AsyncMock(
            return_value=mfa_device
        )
        handler.mfa_service.verify_totp_code = Mock(return_value=False)
        handler.user_repository.save = AsyncMock()

        command = VerifyMfaChallengeCommand(
            user_id=str(uuid4()),
            session_id=str(uuid4()),
            verification_code="wrong_code",
        )

        # Act & Assert
        with pytest.raises(InvalidMfaCodeError):
            await handler.handle(command)

        user.record_failed_mfa_attempt.assert_called_once()
        mfa_device.record_failed_attempt.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_mfa_challenge_device_locked(self, handler):
        """Test MFA challenge verification with locked device."""
        # Arrange
        user = Mock(spec=User)
        user.mfa_enabled = True

        session = Mock()
        session.requires_mfa = True

        mfa_device = Mock(spec=MfaDevice)
        mfa_device.is_locked = True
        mfa_device.locked_until = datetime.now(UTC) + timedelta(minutes=30)

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.session_repository.find_by_id = AsyncMock(return_value=session)
        handler.user_repository.get_primary_mfa_device = AsyncMock(
            return_value=mfa_device
        )

        command = VerifyMfaChallengeCommand(
            user_id=str(uuid4()), session_id=str(uuid4()), verification_code="123456"
        )

        # Act & Assert
        with pytest.raises(ValueError, match="locked"):
            await handler.handle(command)


class TestDisableMfaCommandHandler:
    """Test disable MFA command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_password_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return DisableMfaCommandHandler(
            user_repository=mock_user_repo,
            password_service=mock_password_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_mfa_disable(self, handler):
        """Test successful MFA disable."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = True
        user.validate_password = Mock(return_value=True)
        user.disable_mfa = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.save = AsyncMock()

        command = DisableMfaCommand(
            user_id=user_id, password="current_password", reason="Switching devices"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.mfa_disabled is True
        user.validate_password.assert_called_once_with("current_password")
        user.disable_mfa.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_mfa_wrong_password(self, handler):
        """Test MFA disable with wrong password."""
        # Arrange
        user = Mock(spec=User)
        user.mfa_enabled = True
        user.validate_password = Mock(return_value=False)
        user.record_failed_password_attempt = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.save = AsyncMock()

        command = DisableMfaCommand(user_id=str(uuid4()), password="wrong_password")

        # Act & Assert
        with pytest.raises(ValueError, match="password"):
            await handler.handle(command)

        user.record_failed_password_attempt.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_mfa_not_enabled(self, handler):
        """Test disabling MFA when not enabled."""
        # Arrange
        user = Mock(spec=User)
        user.mfa_enabled = False

        handler.user_repository.find_by_id = AsyncMock(return_value=user)

        command = DisableMfaCommand(user_id=str(uuid4()), password="password")

        # Act & Assert
        with pytest.raises(MfaNotSetupError):
            await handler.handle(command)


class TestGenerateBackupCodesCommandHandler:
    """Test generate backup codes command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_mfa_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return GenerateBackupCodesCommandHandler(
            user_repository=mock_user_repo,
            mfa_service=mock_mfa_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_backup_codes_generation(self, handler):
        """Test successful backup codes generation."""
        # Arrange
        user_id = str(uuid4())
        new_codes = [
            f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
            for _ in range(10)
        ]

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = True
        user.regenerate_backup_codes = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.mfa_service.generate_backup_codes = Mock(return_value=new_codes)
        handler.user_repository.save = AsyncMock()

        command = GenerateBackupCodesCommand(user_id=user_id, invalidate_existing=True)

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert len(result.backup_codes) == 10
        assert result.codes_generated == 10
        user.regenerate_backup_codes.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_backup_codes_mfa_not_enabled(self, handler):
        """Test backup codes generation when MFA not enabled."""
        # Arrange
        user = Mock(spec=User)
        user.mfa_enabled = False

        handler.user_repository.find_by_id = AsyncMock(return_value=user)

        command = GenerateBackupCodesCommand(user_id=str(uuid4()))

        # Act & Assert
        with pytest.raises(MfaNotSetupError):
            await handler.handle(command)


class TestGetMfaDevicesQueryHandler:
    """Test get MFA devices query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_cache = Mock()

        return GetMfaDevicesQueryHandler(
            user_repository=mock_user_repo, cache=mock_cache
        )

    @pytest.mark.asyncio
    async def test_get_mfa_devices_success(self, handler):
        """Test getting MFA devices successfully."""
        # Arrange
        user_id = str(uuid4())

        devices = []
        for i, method in enumerate(
            [MFAMethod.TOTP, MFAMethod.SMS, MFAMethod.HARDWARE_KEY]
        ):
            device = Mock(spec=MfaDevice)
            device.id = str(uuid4())
            device.name = f"Device {i+1}"
            device.method = method
            device.is_primary = i == 0
            device.is_active = True
            device.created_at = datetime.now(UTC) - timedelta(days=i)
            device.last_used_at = datetime.now(UTC) - timedelta(hours=i)
            devices.append(device)

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.get_user_mfa_devices = AsyncMock(return_value=devices)
        handler.cache.set = Mock()

        query = GetMfaDevicesQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.user_id == user_id
        assert len(result.devices) == 3
        assert result.total_devices == 3
        assert result.primary_device_id == devices[0].id
        assert any(d.method == MFAMethod.TOTP for d in result.devices)

    @pytest.mark.asyncio
    async def test_get_mfa_devices_filtered_by_method(self, handler):
        """Test getting MFA devices filtered by method."""
        # Arrange
        user_id = str(uuid4())

        totp_devices = [
            Mock(spec=MfaDevice, method=MFAMethod.TOTP),
            Mock(spec=MfaDevice, method=MFAMethod.TOTP),
        ]

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.get_user_mfa_devices = AsyncMock(
            return_value=totp_devices
        )
        handler.cache.set = Mock()

        query = GetMfaDevicesQuery(user_id=user_id, method_filter=MFAMethod.TOTP)

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.devices) == 2
        assert all(d.method == MFAMethod.TOTP for d in result.devices)

    @pytest.mark.asyncio
    async def test_get_mfa_devices_user_not_found(self, handler):
        """Test getting MFA devices for non-existent user."""
        # Arrange
        handler.cache.get = Mock(return_value=None)
        handler.user_repository.get_user_mfa_devices = AsyncMock(
            side_effect=UserNotFoundError("User not found")
        )

        query = GetMfaDevicesQuery(user_id=str(uuid4()))

        # Act & Assert
        with pytest.raises(UserNotFoundError):
            await handler.handle(query)


class TestGetMfaStatusQueryHandler:
    """Test get MFA status query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_cache = Mock()

        return GetMfaStatusQueryHandler(
            user_repository=mock_user_repo, cache=mock_cache
        )

    @pytest.mark.asyncio
    async def test_get_mfa_status_enabled(self, handler):
        """Test getting MFA status when enabled."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = True
        user.mfa_devices = [
            Mock(spec=MfaDevice, method=MFAMethod.TOTP, is_primary=True),
            Mock(spec=MfaDevice, method=MFAMethod.SMS, is_primary=False),
        ]
        user.backup_codes_remaining = 8

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.cache.set = Mock()

        query = GetMfaStatusQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.user_id == user_id
        assert result.mfa_enabled is True
        assert result.device_count == 2
        assert result.primary_method == MFAMethod.TOTP
        assert result.backup_codes_remaining == 8
        assert MFAMethod.TOTP in result.available_methods
        assert MFAMethod.SMS in result.available_methods

    @pytest.mark.asyncio
    async def test_get_mfa_status_disabled(self, handler):
        """Test getting MFA status when disabled."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.mfa_enabled = False
        user.mfa_devices = []
        user.backup_codes_remaining = 0

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.cache.set = Mock()

        query = GetMfaStatusQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.mfa_enabled is False
        assert result.device_count == 0
        assert result.primary_method is None
        assert result.backup_codes_remaining == 0
        assert len(result.available_methods) == 0
