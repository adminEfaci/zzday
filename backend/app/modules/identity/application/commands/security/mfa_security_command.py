"""
MFA security command implementation.

Handles multi-factor authentication security operations including MFA setup,
validation, backup codes, device management, and security analysis.
"""

import base64
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from io import BytesIO
from typing import Any
from uuid import UUID

import qrcode

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
)
from app.modules.identity.application.dtos.request import MfaSecurityRequest
from app.modules.identity.application.dtos.response import MfaSecurityResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeviceType,
    MfaMethod,
    MfaStatus,
    NotificationType,
    RiskLevel,
)
from app.modules.identity.domain.events import (
    MfaConfigured,
    MfaValidated,
    SuspiciousMfaActivity,
)
from app.modules.identity.domain.exceptions import (
    MfaConfigurationError,
    MfaSecurityError,
    MfaValidationError,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
    MfaService,
    SecurityService,
    SmsService,
    TotpService,
    ValidationService,
)


class MfaOperation(Enum):
    """Type of MFA security operation."""
    SETUP_TOTP = "setup_totp"
    SETUP_SMS = "setup_sms"
    SETUP_EMAIL = "setup_email"
    VALIDATE_CODE = "validate_code"
    DISABLE_MFA = "disable_mfa"
    GENERATE_BACKUP_CODES = "generate_backup_codes"
    REGISTER_DEVICE = "register_device"
    REVOKE_DEVICE = "revoke_device"
    ANALYZE_SECURITY = "analyze_security"
    AUDIT_MFA_USAGE = "audit_mfa_usage"


class BackupCodeFormat(Enum):
    """Format for backup codes."""
    NUMERIC_8 = "numeric_8"  # 12345678
    ALPHANUMERIC_8 = "alphanumeric_8"  # A1B2C3D4
    HYPHENATED_10 = "hyphenated_10"  # 12345-67890
    CUSTOM = "custom"


@dataclass
class MfaConfig:
    """MFA configuration settings."""
    methods_enabled: list[MfaMethod]
    require_mfa: bool = True
    allow_backup_codes: bool = True
    backup_codes_count: int = 10
    backup_code_format: BackupCodeFormat = BackupCodeFormat.ALPHANUMERIC_8
    totp_window_seconds: int = 30
    totp_digits: int = 6
    totp_algorithm: str = "SHA1"
    sms_rate_limit: int = 3  # per hour
    email_rate_limit: int = 5  # per hour
    device_trust_duration_days: int = 30
    max_trusted_devices: int = 5
    force_mfa_setup_days: int = 7
    allow_remember_device: bool = True


@dataclass
class MfaAnalysis:
    """Result of MFA security analysis."""
    user_id: UUID
    methods_configured: list[MfaMethod]
    active_devices: int
    trusted_devices: int
    backup_codes_remaining: int
    last_used: datetime | None
    usage_frequency: dict[str, int]
    security_score: float
    risk_factors: list[str]
    recommendations: list[str]
    compliance_status: str


class MfaSecurityCommand(Command[MfaSecurityResponse]):
    """Command to handle MFA security operations."""
    
    def __init__(
        self,
        operation_type: MfaOperation,
        user_id: UUID,
        mfa_method: MfaMethod | None = None,
        verification_code: str | None = None,
        device_name: str | None = None,
        device_type: DeviceType | None = None,
        device_fingerprint: str | None = None,
        phone_number: str | None = None,
        email_address: str | None = None,
        backup_code: str | None = None,
        remember_device: bool = False,
        trust_device: bool = False,
        mfa_config: MfaConfig | None = None,
        force_setup: bool = False,
        generate_qr_code: bool = True,
        include_recovery_info: bool = True,
        validate_device_security: bool = True,
        check_anomalies: bool = True,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None,
        dry_run: bool = False,
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.user_id = user_id
        self.mfa_method = mfa_method
        self.verification_code = verification_code
        self.device_name = device_name
        self.device_type = device_type
        self.device_fingerprint = device_fingerprint
        self.phone_number = phone_number
        self.email_address = email_address
        self.backup_code = backup_code
        self.remember_device = remember_device
        self.trust_device = trust_device
        self.mfa_config = mfa_config or MfaConfig(methods_enabled=[MfaMethod.TOTP])
        self.force_setup = force_setup
        self.generate_qr_code = generate_qr_code
        self.include_recovery_info = include_recovery_info
        self.validate_device_security = validate_device_security
        self.check_anomalies = check_anomalies
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.session_id = session_id
        self.dry_run = dry_run
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class MfaSecurityCommandHandler(CommandHandler[MfaSecurityCommand, MfaSecurityResponse]):
    """Handler for MFA security operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        mfa_repository: IMfaRepository,
        device_repository: IDeviceRepository,
        backup_code_repository: IBackupCodeRepository,
        mfa_service: MfaService,
        totp_service: TotpService,
        sms_service: SmsService,
        security_service: SecurityService,
        validation_service: ValidationService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._mfa_repository = mfa_repository
        self._device_repository = device_repository
        self._backup_code_repository = backup_code_repository
        self._mfa_service = mfa_service
        self._totp_service = totp_service
        self._sms_service = sms_service
        self._security_service = security_service
        self._validation_service = validation_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.MFA_SECURITY_OPERATION,
        resource_type="mfa_security",
        include_request=True,
        include_response=True,
        include_ip_address=True
    )
    @validate_request(MfaSecurityRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("security.mfa.manage")
    async def handle(self, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """
        Handle MFA security operations.
        
        Supports multiple operations:
        - setup_totp: Set up TOTP authentication
        - setup_sms: Set up SMS authentication
        - setup_email: Set up email authentication  
        - validate_code: Validate MFA code
        - disable_mfa: Disable MFA for user
        - generate_backup_codes: Generate backup codes
        - register_device: Register trusted device
        - revoke_device: Revoke device trust
        - analyze_security: Analyze MFA security posture
        - audit_mfa_usage: Audit MFA usage patterns
        
        Returns:
            MfaSecurityResponse with operation results
        """
        async with self._unit_of_work:
            # Load user context
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise MfaConfigurationError(f"User {command.user_id} not found")
            
            # Check for suspicious activity if enabled
            if command.check_anomalies:
                await self._check_mfa_anomalies(user, command)
            
            # Route to appropriate handler based on operation type
            if command.operation_type == MfaOperation.SETUP_TOTP:
                return await self._handle_totp_setup(user, command)
            if command.operation_type == MfaOperation.SETUP_SMS:
                return await self._handle_sms_setup(user, command)
            if command.operation_type == MfaOperation.SETUP_EMAIL:
                return await self._handle_email_setup(user, command)
            if command.operation_type == MfaOperation.VALIDATE_CODE:
                return await self._handle_code_validation(user, command)
            if command.operation_type == MfaOperation.DISABLE_MFA:
                return await self._handle_mfa_disable(user, command)
            if command.operation_type == MfaOperation.GENERATE_BACKUP_CODES:
                return await self._handle_backup_code_generation(user, command)
            if command.operation_type == MfaOperation.REGISTER_DEVICE:
                return await self._handle_device_registration(user, command)
            if command.operation_type == MfaOperation.REVOKE_DEVICE:
                return await self._handle_device_revocation(user, command)
            if command.operation_type == MfaOperation.ANALYZE_SECURITY:
                return await self._handle_security_analysis(user, command)
            if command.operation_type == MfaOperation.AUDIT_MFA_USAGE:
                return await self._handle_usage_audit(user, command)
            raise MfaSecurityError(f"Unsupported operation type: {command.operation_type.value}")
    
    async def _handle_totp_setup(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle TOTP (authenticator app) setup."""
        # 1. Check if TOTP is already configured
        existing_totp = await self._mfa_repository.get_user_mfa_method(user.id, MfaMethod.TOTP)
        if existing_totp and not command.force_setup:
            raise MfaConfigurationError("TOTP is already configured for this user")
        
        # 2. Generate TOTP secret
        totp_secret = self._totp_service.generate_secret()
        
        # 3. Create TOTP configuration
        totp_config = {
            "id": UUID(),
            "user_id": user.id,
            "method": MfaMethod.TOTP.value,
            "secret": await self._security_service.encrypt(totp_secret),
            "status": MfaStatus.PENDING.value if not command.dry_run else MfaStatus.CONFIGURED.value,
            "algorithm": command.mfa_config.totp_algorithm,
            "digits": command.mfa_config.totp_digits,
            "period": command.mfa_config.totp_window_seconds,
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by,
            "metadata": {
                "ip_address": command.ip_address,
                "user_agent": command.user_agent,
                "setup_method": "manual"
            }
        }
        
        if not command.dry_run:
            mfa_record = await self._mfa_repository.create(totp_config)
        else:
            mfa_record = type('MockMfaRecord', (), totp_config)()
        
        # 4. Generate QR code if requested
        qr_code_data = None
        if command.generate_qr_code:
            qr_code_data = await self._generate_totp_qr_code(
                user,
                totp_secret,
                command.mfa_config
            )
        
        # 5. Generate backup codes if enabled
        backup_codes = []
        if command.mfa_config.allow_backup_codes and command.include_recovery_info:
            backup_codes = await self._generate_backup_codes(
                user.id,
                command.mfa_config,
                command.dry_run
            )
        
        # 6. Log TOTP setup
        await self._log_mfa_operation(user, "totp_setup", command)
        
        # 7. Send setup notification
        if not command.dry_run:
            await self._send_mfa_setup_notification(user, MfaMethod.TOTP, command)
        
        # 8. Publish domain event
        if not command.dry_run:
            await self._event_bus.publish(
                MfaConfigured(
                    aggregate_id=user.id,
                    user_id=user.id,
                    mfa_method=MfaMethod.TOTP.value,
                    mfa_id=mfa_record.id,
                    configured_by=command.initiated_by
                )
            )
        
        # 9. Commit transaction
        await self._unit_of_work.commit()
        
        # 10. Generate response
        return MfaSecurityResponse(
            success=True,
            operation_type=command.operation_type.value,
            user_id=user.id,
            mfa_method=MfaMethod.TOTP.value,
            mfa_id=mfa_record.id,
            setup_data={
                "secret": totp_secret if not command.dry_run else "***masked***",
                "qr_code": qr_code_data,
                "backup_codes": backup_codes if command.include_recovery_info else [],
                "algorithm": command.mfa_config.totp_algorithm,
                "digits": command.mfa_config.totp_digits,
                "period": command.mfa_config.totp_window_seconds
            },
            dry_run=command.dry_run,
            message="TOTP setup completed successfully"
        )
    
    async def _generate_totp_qr_code(
        self,
        user: User,
        secret: str,
        config: MfaConfig
    ) -> dict[str, Any]:
        """Generate QR code for TOTP setup."""
        # Create TOTP URI
        issuer = "EzzDay"
        account = f"{user.username}@{issuer}"
        
        totp_uri = (
            f"otpauth://totp/{account}?"
            f"secret={secret}&"
            f"issuer={issuer}&"
            f"algorithm={config.totp_algorithm}&"
            f"digits={config.totp_digits}&"
            f"period={config.totp_window_seconds}"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            "uri": totp_uri,
            "qr_code_image": f"data:image/png;base64,{qr_code_base64}",
            "manual_entry_key": secret,
            "account": account,
            "issuer": issuer
        }
    
    async def _generate_backup_codes(
        self,
        user_id: UUID,
        config: MfaConfig,
        dry_run: bool
    ) -> list[str]:
        """Generate backup codes for MFA recovery."""
        backup_codes = []
        
        for _ in range(config.backup_codes_count):
            if config.backup_code_format == BackupCodeFormat.NUMERIC_8:
                code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            elif config.backup_code_format == BackupCodeFormat.ALPHANUMERIC_8:
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                code = ''.join([secrets.choice(charset) for _ in range(8)])
            elif config.backup_code_format == BackupCodeFormat.HYPHENATED_10:
                part1 = ''.join([str(secrets.randbelow(10)) for _ in range(5)])
                part2 = ''.join([str(secrets.randbelow(10)) for _ in range(5)])
                code = f"{part1}-{part2}"
            else:
                # Default to alphanumeric
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                code = ''.join([secrets.choice(charset) for _ in range(8)])
            
            backup_codes.append(code)
            
            # Store in database if not dry run
            if not dry_run:
                backup_code_data = {
                    "id": UUID(),
                    "user_id": user_id,
                    "code_hash": await self._security_service.hash(code),
                    "used": False,
                    "created_at": datetime.now(UTC),
                    "expires_at": datetime.now(UTC) + timedelta(days=365)
                }
                await self._backup_code_repository.create(backup_code_data)
        
        return backup_codes
    
    async def _handle_sms_setup(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle SMS-based MFA setup."""
        # 1. Validate phone number
        if not command.phone_number:
            raise MfaConfigurationError("Phone number is required for SMS setup")
        
        normalized_phone = self._validation_service.normalize_phone_number(command.phone_number)
        if not self._validation_service.validate_phone_number(normalized_phone):
            raise MfaValidationError("Invalid phone number format")
        
        # 2. Check rate limits
        if not await self._check_sms_rate_limit(user.id, command.mfa_config.sms_rate_limit):
            raise MfaSecurityError("SMS rate limit exceeded")
        
        # 3. Generate verification code
        verification_code = self._generate_verification_code(6)
        
        # 4. Send SMS verification
        if not command.dry_run:
            sms_result = await self._sms_service.send_verification_sms(
                normalized_phone,
                verification_code,
                "EzzDay MFA Setup"
            )
            
            if not sms_result.get("success"):
                raise MfaConfigurationError(f"Failed to send SMS: {sms_result.get('error')}")
        
        # 5. Store pending SMS configuration
        sms_config = {
            "id": UUID(),
            "user_id": user.id,
            "method": MfaMethod.SMS.value,
            "phone_number": normalized_phone,
            "verification_code_hash": await self._security_service.hash(verification_code),
            "status": MfaStatus.PENDING.value,
            "expires_at": datetime.now(UTC) + timedelta(minutes=10),
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by
        }
        
        if not command.dry_run:
            mfa_record = await self._mfa_repository.create(sms_config)
        else:
            mfa_record = type('MockMfaRecord', (), sms_config)()
        
        # 6. Log SMS setup attempt
        await self._log_mfa_operation(user, "sms_setup", command, {
            "phone_number": self._mask_phone_number(normalized_phone)
        })
        
        # 7. Commit transaction
        await self._unit_of_work.commit()
        
        return MfaSecurityResponse(
            success=True,
            operation_type=command.operation_type.value,
            user_id=user.id,
            mfa_method=MfaMethod.SMS.value,
            mfa_id=mfa_record.id,
            setup_data={
                "phone_number": self._mask_phone_number(normalized_phone),
                "verification_required": True,
                "expires_at": sms_config["expires_at"].isoformat()
            },
            dry_run=command.dry_run,
            message="SMS verification code sent. Complete setup by validating the code."
        )
    
    async def _handle_email_setup(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle email-based MFA setup."""
        # 1. Determine email address
        email_address = command.email_address or user.email
        if not email_address:
            raise MfaConfigurationError("Email address is required for email MFA setup")
        
        if not self._validation_service.validate_email(email_address):
            raise MfaValidationError("Invalid email address format")
        
        # 2. Check rate limits
        if not await self._check_email_rate_limit(user.id, command.mfa_config.email_rate_limit):
            raise MfaSecurityError("Email rate limit exceeded")
        
        # 3. Generate verification code
        verification_code = self._generate_verification_code(8)
        
        # 4. Send email verification
        if not command.dry_run:
            await self._email_service.send_email(
                EmailContext(
                    recipient=email_address,
                    subject="EzzDay MFA Setup - Verification Code",
                    template="mfa_email_verification",
                    variables={
                        "username": user.username,
                        "verification_code": verification_code,
                        "expires_minutes": 10
                    }
                )
            )
        
        # 5. Store pending email configuration
        email_config = {
            "id": UUID(),
            "user_id": user.id,
            "method": MfaMethod.EMAIL.value,
            "email_address": email_address,
            "verification_code_hash": await self._security_service.hash(verification_code),
            "status": MfaStatus.PENDING.value,
            "expires_at": datetime.now(UTC) + timedelta(minutes=10),
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by
        }
        
        if not command.dry_run:
            mfa_record = await self._mfa_repository.create(email_config)
        else:
            mfa_record = type('MockMfaRecord', (), email_config)()
        
        # 6. Log email setup attempt
        await self._log_mfa_operation(user, "email_setup", command, {
            "email_address": self._mask_email_address(email_address)
        })
        
        # 7. Commit transaction
        await self._unit_of_work.commit()
        
        return MfaSecurityResponse(
            success=True,
            operation_type=command.operation_type.value,
            user_id=user.id,
            mfa_method=MfaMethod.EMAIL.value,
            mfa_id=mfa_record.id,
            setup_data={
                "email_address": self._mask_email_address(email_address),
                "verification_required": True,
                "expires_at": email_config["expires_at"].isoformat()
            },
            dry_run=command.dry_run,
            message="Email verification code sent. Complete setup by validating the code."
        )
    
    async def _handle_code_validation(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle MFA code validation."""
        if not command.verification_code:
            raise MfaValidationError("Verification code is required")
        
        # 1. Try to validate against all configured MFA methods
        validation_result = None
        mfa_method_used = None
        
        # Check TOTP
        totp_mfa = await self._mfa_repository.get_user_mfa_method(user.id, MfaMethod.TOTP)
        if totp_mfa and totp_mfa.status == MfaStatus.CONFIGURED.value:
            totp_secret = await self._security_service.decrypt(totp_mfa.secret)
            if self._totp_service.verify_token(totp_secret, command.verification_code):
                validation_result = {"success": True, "method": "totp"}
                mfa_method_used = MfaMethod.TOTP
        
        # Check SMS if TOTP failed
        if not validation_result:
            sms_mfa = await self._mfa_repository.get_pending_verification(user.id, MfaMethod.SMS)
            if sms_mfa and await self._security_service.verify_hash(command.verification_code, sms_mfa.verification_code_hash):
                if sms_mfa.expires_at > datetime.now(UTC):
                    validation_result = {"success": True, "method": "sms"}
                    mfa_method_used = MfaMethod.SMS
                    # Activate SMS MFA
                    await self._mfa_repository.activate_mfa_method(sms_mfa.id)
        
        # Check Email if others failed
        if not validation_result:
            email_mfa = await self._mfa_repository.get_pending_verification(user.id, MfaMethod.EMAIL)
            if email_mfa and await self._security_service.verify_hash(command.verification_code, email_mfa.verification_code_hash):
                if email_mfa.expires_at > datetime.now(UTC):
                    validation_result = {"success": True, "method": "email"}
                    mfa_method_used = MfaMethod.EMAIL
                    # Activate Email MFA
                    await self._mfa_repository.activate_mfa_method(email_mfa.id)
        
        # Check backup codes
        if not validation_result:
            backup_code = await self._backup_code_repository.find_valid_code(user.id, command.verification_code)
            if backup_code:
                validation_result = {"success": True, "method": "backup_code"}
                mfa_method_used = "backup_code"
                # Mark backup code as used
                await self._backup_code_repository.mark_used(backup_code.id)
        
        if not validation_result:
            # Log failed validation attempt
            await self._log_mfa_operation(user, "validation_failed", command)
            raise MfaValidationError("Invalid verification code")
        
        # 2. Handle device registration if requested
        device_registered = False
        if command.remember_device and command.device_fingerprint:
            device_registered = await self._register_trusted_device(user, command)
        
        # 3. Update MFA usage statistics
        await self._update_mfa_usage_stats(user.id, mfa_method_used)
        
        # 4. Log successful validation
        await self._log_mfa_operation(user, "validation_success", command, {
            "method_used": validation_result["method"],
            "device_registered": device_registered
        })
        
        # 5. Publish domain event
        await self._event_bus.publish(
            MfaValidated(
                aggregate_id=user.id,
                user_id=user.id,
                mfa_method=validation_result["method"],
                device_fingerprint=command.device_fingerprint,
                ip_address=command.ip_address,
                validated_at=datetime.now(UTC)
            )
        )
        
        # 6. Commit transaction
        await self._unit_of_work.commit()
        
        return MfaSecurityResponse(
            success=True,
            operation_type=command.operation_type.value,
            user_id=user.id,
            validation_result={
                "valid": True,
                "method_used": validation_result["method"],
                "device_registered": device_registered,
                "validated_at": datetime.now(UTC).isoformat()
            },
            message="MFA code validated successfully"
        )
    
    def _generate_verification_code(self, length: int) -> str:
        """Generate numeric verification code."""
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for logging."""
        if len(phone) > 4:
            return f"***-***-{phone[-4:]}"
        return "***-****"
    
    def _mask_email_address(self, email: str) -> str:
        """Mask email address for logging."""
        if '@' in email:
            local, domain = email.split('@', 1)
            if len(local) > 2:
                return f"{local[:2]}***@{domain}"
            return f"***@{domain}"
        return "***@***.***"
    
    async def _check_sms_rate_limit(self, user_id: UUID, limit: int) -> bool:
        """Check SMS rate limit."""
        recent_attempts = await self._mfa_repository.count_recent_sms_attempts(
            user_id,
            datetime.now(UTC) - timedelta(hours=1)
        )
        return recent_attempts < limit
    
    async def _check_email_rate_limit(self, user_id: UUID, limit: int) -> bool:
        """Check email rate limit."""
        recent_attempts = await self._mfa_repository.count_recent_email_attempts(
            user_id,
            datetime.now(UTC) - timedelta(hours=1)
        )
        return recent_attempts < limit
    
    async def _register_trusted_device(self, user: User, command: MfaSecurityCommand) -> bool:
        """Register device as trusted for MFA."""
        if not command.device_fingerprint:
            return False
        
        try:
            device_data = {
                "id": UUID(),
                "user_id": user.id,
                "device_fingerprint": command.device_fingerprint,
                "device_name": command.device_name or "Unknown Device",
                "device_type": command.device_type.value if command.device_type else DeviceType.UNKNOWN.value,
                "trusted": command.trust_device,
                "ip_address": command.ip_address,
                "user_agent": command.user_agent,
                "registered_at": datetime.now(UTC),
                "expires_at": datetime.now(UTC) + timedelta(days=command.mfa_config.device_trust_duration_days),
                "metadata": {
                    "registration_method": "mfa_validation",
                    "session_id": str(command.session_id) if command.session_id else None
                }
            }
            
            await self._device_repository.create(device_data)
            return True
            
        except Exception:
            return False
    
    async def _update_mfa_usage_stats(self, user_id: UUID, method: MfaMethod | str) -> None:
        """Update MFA usage statistics."""
        method_name = method.value if hasattr(method, 'value') else str(method)
        
        usage_data = {
            "user_id": user_id,
            "method": method_name,
            "used_at": datetime.now(UTC),
            "ip_address": getattr(self, '_current_ip', None),
            "user_agent": getattr(self, '_current_user_agent', None)
        }
        
        await self._mfa_repository.record_usage(usage_data)
    
    async def _check_mfa_anomalies(self, user: User, command: MfaSecurityCommand) -> None:
        """Check for suspicious MFA activity."""
        anomalies = []
        
        # Check for unusual IP addresses
        if command.ip_address:
            recent_ips = await self._mfa_repository.get_recent_ip_addresses(user.id, days=30)
            if command.ip_address not in recent_ips and len(recent_ips) > 0:
                anomalies.append("New IP address")
        
        # Check for rapid successive attempts
        recent_attempts = await self._mfa_repository.count_recent_attempts(
            user.id,
            datetime.now(UTC) - timedelta(minutes=5)
        )
        if recent_attempts > 10:
            anomalies.append("High frequency of attempts")
        
        # Check for unusual time patterns
        current_hour = datetime.now(UTC).hour
        usual_hours = await self._mfa_repository.get_usual_activity_hours(user.id)
        if usual_hours and current_hour not in usual_hours:
            anomalies.append("Unusual time of activity")
        
        if anomalies:
            await self._event_bus.publish(
                SuspiciousMfaActivity(
                    aggregate_id=user.id,
                    user_id=user.id,
                    anomalies=anomalies,
                    ip_address=command.ip_address,
                    user_agent=command.user_agent,
                    detected_at=datetime.now(UTC)
                )
            )
    
    async def _send_mfa_setup_notification(self, user: User, method: MfaMethod, command: MfaSecurityCommand) -> None:
        """Send notification about MFA setup."""
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.MFA_CONFIGURED,
                channel="email",
                template_id="mfa_setup_complete",
                template_data={
                    "username": user.username,
                    "mfa_method": method.value,
                    "setup_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "ip_address": command.ip_address
                },
                priority="medium"
            )
        )
    
    async def _log_mfa_operation(
        self,
        user: User,
        operation: str,
        command: MfaSecurityCommand,
        additional_details: dict[str, Any] | None = None
    ) -> None:
        """Log MFA operation."""
        details = {
            "operation": operation,
            "operation_type": command.operation_type.value,
            "mfa_method": command.mfa_method.value if command.mfa_method else None,
            "ip_address": command.ip_address,
            "user_agent": command.user_agent,
            "session_id": str(command.session_id) if command.session_id else None,
            "dry_run": command.dry_run
        }
        
        if additional_details:
            details.update(additional_details)
        
        await self._audit_service.log_action(
            AuditContext(
                action=getattr(AuditAction, f"MFA_{operation.upper()}", AuditAction.MFA_SECURITY_OPERATION),
                actor_id=command.initiated_by,
                resource_type="mfa_security",
                resource_id=user.id,
                details=details,
                risk_level=RiskLevel.MEDIUM.value if "failed" in operation else RiskLevel.LOW.value
            )
        )
    
    # Placeholder implementations for other operations
    async def _handle_mfa_disable(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle MFA disable operation."""
        raise NotImplementedError("MFA disable not yet implemented")
    
    async def _handle_backup_code_generation(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle backup code generation."""
        raise NotImplementedError("Backup code generation not yet implemented")
    
    async def _handle_device_registration(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle device registration."""
        raise NotImplementedError("Device registration not yet implemented")
    
    async def _handle_device_revocation(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle device revocation."""
        raise NotImplementedError("Device revocation not yet implemented")
    
    async def _handle_security_analysis(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle MFA security analysis."""
        raise NotImplementedError("Security analysis not yet implemented")
    
    async def _handle_usage_audit(self, user: User, command: MfaSecurityCommand) -> MfaSecurityResponse:
        """Handle MFA usage audit."""
        raise NotImplementedError("Usage audit not yet implemented")