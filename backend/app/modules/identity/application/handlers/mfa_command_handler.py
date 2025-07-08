"""
Consolidated MFA Command Handler

Consolidates MFA-related commands into a single handler.
Addresses the service explosion issue by grouping related MFA operations.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IEmailService,
    IMFADeviceRepository,
    IMFAProviderFactory,
    ISessionRepository,
    ISMSService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    authorize,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    DisableMFAParams,
    GenerateBackupCodesParams,
    SetupMFAParams,
    VerifyMFAChallengeParams,
    VerifyMFASetupParams,
)
from app.modules.identity.application.dtos.request import (
    DisableMFARequest,
    GenerateBackupCodesRequest,
    SetupMFARequest,
    VerifyMFAChallengeRequest,
    VerifyMFASetupRequest,
)
from app.modules.identity.application.dtos.response import (
    BackupCodesResponse,
    MFAChallengeResponse,
    MFASetupResponse,
    MFAVerificationResponse,
)
from app.modules.identity.domain.entities import MFADevice, Session, User
from app.modules.identity.domain.enums import (
    AuditAction,
    MFAMethod,
    Permission,
    SessionType,
)
from app.modules.identity.domain.events import (
    MFABackupCodesGenerated,
    MFAChallengeCompleted,
    MFAChallengeFailed,
    MFADeviceCreated,
    MFADeviceDisabled,
    MFADeviceVerified,
    MFADisabled,
    MFAEnabled,
)
from app.modules.identity.domain.exceptions import (
    InvalidCodeError,
    InvalidOperationError,
    MFANotEnabledError,
    MaxAttemptsExceededError,
    SessionNotFoundError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import MFADomainService
from app.modules.identity.domain.specifications import ActiveUserSpecification
from app.modules.identity.domain.value_objects import UserId
from app.modules.identity.application.services.shared.security_utils import SecurityUtils
from app.modules.identity.application.services.shared.validation_utils import ValidationUtils


# Consolidated Commands
@dataclass
class SetupMFACommand(Command[MFASetupResponse]):
    """Command to setup MFA for a user."""
    user_id: UUID
    params: SetupMFAParams


@dataclass
class VerifyMFASetupCommand(Command[MFAVerificationResponse]):
    """Command to verify MFA setup."""
    user_id: UUID
    params: VerifyMFASetupParams


@dataclass
class DisableMFACommand(Command[None]):
    """Command to disable MFA for a user."""
    user_id: UUID
    params: DisableMFAParams


@dataclass
class GenerateBackupCodesCommand(Command[BackupCodesResponse]):
    """Command to generate backup codes."""
    user_id: UUID
    params: GenerateBackupCodesParams


@dataclass
class VerifyMFAChallengeCommand(Command[MFAVerificationResponse]):
    """Command to verify MFA challenge during login."""
    session_id: UUID
    params: VerifyMFAChallengeParams


# Dependency Groups
@dataclass
class MFARepositories:
    """Repository dependencies for MFA operations."""
    user_repository: IUserRepository
    mfa_device_repository: IMFADeviceRepository
    session_repository: ISessionRepository


@dataclass
class MFAServices:
    """Service dependencies for MFA operations."""
    mfa_domain_service: MFADomainService
    mfa_provider_factory: IMFAProviderFactory
    email_service: IEmailService
    sms_service: ISMSService
    cache_service: ICacheService


@dataclass
class MFAInfrastructure:
    """Infrastructure dependencies for MFA operations."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class MFACommandHandler:
    """
    Consolidated handler for all MFA-related commands.
    
    Replaces individual handlers for:
    - SetupMFACommandHandler
    - VerifyMFASetupCommandHandler
    - DisableMFACommandHandler
    - GenerateBackupCodesCommandHandler
    - VerifyMFAChallengeCommandHandler
    """
    
    def __init__(
        self,
        repositories: MFARepositories,
        services: MFAServices,
        infrastructure: MFAInfrastructure,
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._mfa_device_repository = repositories.mfa_device_repository
        self._session_repository = repositories.session_repository
        
        # Service dependencies
        self._mfa_domain_service = services.mfa_domain_service
        self._mfa_provider_factory = services.mfa_provider_factory
        self._email_service = services.email_service
        self._sms_service = services.sms_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work

    @audit_action(action=AuditAction.MFA_SETUP, resource_type="user")
    @authorize(Permission.USER_UPDATE_SELF)
    @validate_request(SetupMFARequest)
    @rate_limit(max_requests=5, window_seconds=3600, strategy='user')
    async def handle_setup_mfa(self, command: SetupMFACommand) -> MFASetupResponse:
        """Setup MFA for a user account."""
        async with self._unit_of_work:
            # Get and validate user
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            if not ActiveUserSpecification().is_satisfied_by(user):
                raise InvalidOperationError("Cannot setup MFA for inactive user")
            
            # Check if method already exists
            existing_devices = await self._mfa_device_repository.get_by_user_and_method(
                user_id=UserId(command.user_id),
                method=command.params.method
            )
            
            if existing_devices and any(d.is_verified for d in existing_devices):
                raise InvalidOperationError(f"MFA method {command.params.method} already configured")
            
            # Get MFA provider
            provider = self._mfa_provider_factory.get_provider(command.params.method)
            
            # Generate setup data based on method
            if command.params.method == MFAMethod.TOTP:
                secret = SecurityUtils.generate_secure_token(16)
                qr_code = await provider.generate_qr_code(
                    user_email=user.email.value,
                    secret=secret
                )
                setup_data = {
                    "secret": secret,
                    "qr_code": qr_code,
                    "manual_entry": secret
                }
            elif command.params.method == MFAMethod.SMS:
                if not command.params.phone_number:
                    raise ValueError("Phone number required for SMS MFA")
                
                if not ValidationUtils.is_valid_phone_number(command.params.phone_number):
                    raise ValueError("Invalid phone number format")
                
                # Send verification code
                verification_code = SecurityUtils.generate_numeric_code(6)
                await self._sms_service.send_verification_code(
                    phone_number=command.params.phone_number,
                    code=verification_code
                )
                
                # Cache verification code
                await self._cache_service.set(
                    key=f"mfa_setup:{command.user_id}:{command.params.method}",
                    value={
                        "code": verification_code,
                        "phone_number": command.params.phone_number,
                        "attempts": 0
                    },
                    ttl=300  # 5 minutes
                )
                
                setup_data = {
                    "phone_number": ValidationUtils.mask_sensitive_data(
                        {"phone": command.params.phone_number}, []
                    )["phone"],
                    "code_sent": True
                }
            elif command.params.method == MFAMethod.EMAIL:
                # Send verification code to email
                verification_code = SecurityUtils.generate_numeric_code(6)
                await self._email_service.send_mfa_setup_code(
                    email=user.email.value,
                    code=verification_code
                )
                
                # Cache verification code
                await self._cache_service.set(
                    key=f"mfa_setup:{command.user_id}:{command.params.method}",
                    value={
                        "code": verification_code,
                        "email": user.email.value,
                        "attempts": 0
                    },
                    ttl=300  # 5 minutes
                )
                
                setup_data = {
                    "email": ValidationUtils.mask_sensitive_data(
                        {"email": user.email.value}, []
                    )["email"],
                    "code_sent": True
                }
            else:
                raise ValueError(f"Unsupported MFA method: {command.params.method}")
            
            # Create unverified MFA device
            mfa_device = MFADevice(
                user_id=UserId(command.user_id),
                method=command.params.method,
                device_name=command.params.device_name or f"{command.params.method} Device",
                secret=setup_data.get("secret"),
                phone_number=command.params.phone_number,
                is_primary=command.params.set_as_primary,
                is_verified=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            
            await self._mfa_device_repository.create(mfa_device)
            
            # Publish MFA device created event
            await self._event_bus.publish(
                MFADeviceCreated(
                    aggregate_id=user.id.value,
                    device_id=mfa_device.id,
                    method=command.params.method,
                    device_name=mfa_device.device_name
                )
            )
            
            await self._unit_of_work.commit()
            
            return MFASetupResponse(
                device_id=mfa_device.id,
                method=command.params.method,
                setup_data=setup_data,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                success=True,
                message=f"MFA setup initiated for {command.params.method}"
            )

    @audit_action(action=AuditAction.MFA_VERIFY, resource_type="user")
    @rate_limit(max_requests=5, window_seconds=300, strategy='user')
    async def handle_verify_mfa_setup(self, command: VerifyMFASetupCommand) -> MFAVerificationResponse:
        """Verify MFA setup with provided code."""
        async with self._unit_of_work:
            # Get MFA device
            mfa_device = await self._mfa_device_repository.get_by_id(command.params.device_id)
            if not mfa_device or mfa_device.user_id.value != command.user_id:
                raise InvalidOperationError("MFA device not found")
            
            if mfa_device.is_verified:
                raise InvalidOperationError("MFA device already verified")
            
            # Get MFA provider
            provider = self._mfa_provider_factory.get_provider(mfa_device.method)
            
            # Verify based on method
            if mfa_device.method == MFAMethod.TOTP:
                is_valid = await provider.verify_code(
                    secret=mfa_device.secret,
                    code=command.params.code
                )
            else:
                # Get cached setup data
                cache_key = f"mfa_setup:{command.user_id}:{mfa_device.method}"
                setup_data = await self._cache_service.get(cache_key)
                
                if not setup_data:
                    raise InvalidOperationError("Setup session expired")
                
                # Check attempts
                if setup_data["attempts"] >= 5:
                    await self._cache_service.delete(cache_key)
                    raise MaxAttemptsExceededError("Too many failed attempts")
                
                # Verify code
                is_valid = SecurityUtils.constant_time_compare(
                    setup_data["code"], command.params.code
                )
                
                if not is_valid:
                    setup_data["attempts"] += 1
                    await self._cache_service.set(cache_key, setup_data, ttl=300)
            
            if not is_valid:
                raise InvalidCodeError("Invalid verification code")
            
            # Mark device as verified
            mfa_device.verify()
            await self._mfa_device_repository.update(mfa_device)
            
            # Update user MFA status
            user = await self._user_repository.get_by_id(mfa_device.user_id)
            if not user.mfa_enabled:
                user.enable_mfa()
                await self._user_repository.update(user)
                
                # Publish MFA enabled event
                await self._event_bus.publish(
                    MFAEnabled(
                        aggregate_id=user.id.value,
                        method=mfa_device.method,
                        enabled_at=datetime.now(UTC)
                    )
                )
            
            # Generate backup codes if first MFA device
            backup_codes = None
            if command.params.generate_backup_codes:
                backup_codes = SecurityUtils.generate_backup_codes(10, 8)
                await self._store_backup_codes(user.id, backup_codes)
            
            # Clean up cache
            if mfa_device.method != MFAMethod.TOTP:
                await self._cache_service.delete(cache_key)
            
            # Publish device verified event
            await self._event_bus.publish(
                MFADeviceVerified(
                    aggregate_id=user.id.value,
                    device_id=mfa_device.id,
                    method=mfa_device.method
                )
            )
            
            await self._unit_of_work.commit()
            
            return MFAVerificationResponse(
                success=True,
                message="MFA device verified successfully",
                backup_codes=backup_codes
            )

    @audit_action(action=AuditAction.MFA_DISABLE, resource_type="user")
    @authorize(Permission.USER_UPDATE_SELF)
    @validate_request(DisableMFARequest)
    async def handle_disable_mfa(self, command: DisableMFACommand) -> None:
        """Disable MFA for a user account."""
        async with self._unit_of_work:
            # Get and validate user
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            if not user.mfa_enabled:
                raise MFANotEnabledError("MFA is not enabled for this user")
            
            # Verify password for security
            if not await self._verify_user_password(user, command.params.password):
                raise InvalidOperationError("Invalid password")
            
            # Get all MFA devices
            mfa_devices = await self._mfa_device_repository.get_by_user(UserId(command.user_id))
            
            if command.params.device_id:
                # Disable specific device
                device = next((d for d in mfa_devices if d.id == command.params.device_id), None)
                if not device:
                    raise InvalidOperationError("MFA device not found")
                
                device.disable()
                await self._mfa_device_repository.update(device)
                
                # Check if any devices remain
                remaining_devices = [d for d in mfa_devices if d.id != device.id and d.is_verified]
                
                # Publish device disabled event
                await self._event_bus.publish(
                    MFADeviceDisabled(
                        aggregate_id=user.id.value,
                        device_id=device.id,
                        method=device.method
                    )
                )
            else:
                # Disable all MFA
                for device in mfa_devices:
                    device.disable()
                    await self._mfa_device_repository.update(device)
                
                remaining_devices = []
            
            # Update user MFA status if no devices remain
            if not remaining_devices:
                user.disable_mfa()
                await self._user_repository.update(user)
                
                # Clear backup codes
                await self._clear_backup_codes(user.id)
                
                # Publish MFA disabled event
                await self._event_bus.publish(
                    MFADisabled(
                        aggregate_id=user.id.value,
                        disabled_at=datetime.now(UTC)
                    )
                )
            
            await self._unit_of_work.commit()

    @audit_action(action=AuditAction.MFA_BACKUP_CODES, resource_type="user")
    @authorize(Permission.USER_UPDATE_SELF)
    @validate_request(GenerateBackupCodesRequest)
    @rate_limit(max_requests=3, window_seconds=3600, strategy='user')
    async def handle_generate_backup_codes(self, command: GenerateBackupCodesCommand) -> BackupCodesResponse:
        """Generate new backup codes for MFA recovery."""
        async with self._unit_of_work:
            # Get and validate user
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            if not user.mfa_enabled:
                raise MFANotEnabledError("MFA is not enabled for this user")
            
            # Verify password for security
            if not await self._verify_user_password(user, command.params.password):
                raise InvalidOperationError("Invalid password")
            
            # Generate new backup codes
            backup_codes = SecurityUtils.generate_backup_codes(
                count=command.params.count or 10,
                length=8
            )
            
            # Store backup codes (hashed)
            await self._store_backup_codes(user.id, backup_codes)
            
            # Publish backup codes generated event
            await self._event_bus.publish(
                MFABackupCodesGenerated(
                    aggregate_id=user.id.value,
                    codes_count=len(backup_codes),
                    generated_at=datetime.now(UTC)
                )
            )
            
            await self._unit_of_work.commit()
            
            return BackupCodesResponse(
                backup_codes=backup_codes,
                generated_at=datetime.now(UTC),
                success=True,
                message=f"Generated {len(backup_codes)} backup codes"
            )

    @audit_action(action=AuditAction.MFA_CHALLENGE, resource_type="session")
    @rate_limit(max_requests=5, window_seconds=300, strategy='session')
    async def handle_verify_mfa_challenge(self, command: VerifyMFAChallengeCommand) -> MFAVerificationResponse:
        """Verify MFA challenge during login."""
        async with self._unit_of_work:
            # Get session
            session = await self._session_repository.get_by_id(command.session_id)
            if not session:
                raise SessionNotFoundError("Session not found")
            
            if session.session_type != SessionType.MFA_PENDING:
                raise InvalidOperationError("Session is not pending MFA verification")
            
            # Check challenge expiry
            challenge_data = await self._cache_service.get(f"mfa_challenge:{command.session_id}")
            if not challenge_data:
                raise InvalidOperationError("MFA challenge expired")
            
            # Check attempts
            if challenge_data.get("attempts", 0) >= 5:
                await self._terminate_session(session, "max_attempts_exceeded")
                raise MaxAttemptsExceededError("Too many failed attempts")
            
            # Get user and MFA device
            user = await self._user_repository.get_by_id(UserId(session.user_id))
            if not user or not user.mfa_enabled:
                raise InvalidOperationError("User MFA not configured")
            
            # Verify code based on device
            is_valid = False
            if command.params.device_id:
                device = await self._mfa_device_repository.get_by_id(command.params.device_id)
                if device and device.user_id.value == user.id.value and device.is_verified:
                    provider = self._mfa_provider_factory.get_provider(device.method)
                    is_valid = await provider.verify_code(
                        secret=device.secret,
                        code=command.params.code
                    )
                    
                    if is_valid:
                        device.update_last_used()
                        await self._mfa_device_repository.update(device)
            else:
                # Try backup codes
                is_valid = await self._verify_backup_code(user.id, command.params.code)
            
            if not is_valid:
                # Increment attempts
                challenge_data["attempts"] = challenge_data.get("attempts", 0) + 1
                await self._cache_service.set(
                    f"mfa_challenge:{command.session_id}",
                    challenge_data,
                    ttl=300
                )
                
                # Publish failed event
                await self._event_bus.publish(
                    MFAChallengeFailed(
                        aggregate_id=user.id.value,
                        session_id=session.id,
                        attempts=challenge_data["attempts"],
                        method=challenge_data.get("method", MFAMethod.TOTP)
                    )
                )
                
                raise InvalidCodeError("Invalid MFA code")
            
            # Update session
            session.complete_mfa_verification()
            await self._session_repository.update(session)
            
            # Clear challenge data
            await self._cache_service.delete(f"mfa_challenge:{command.session_id}")
            
            # Publish success event
            await self._event_bus.publish(
                MFAChallengeCompleted(
                    aggregate_id=user.id.value,
                    session_id=session.id,
                    method=challenge_data.get("method", MFAMethod.TOTP),
                    device_id=command.params.device_id
                )
            )
            
            await self._unit_of_work.commit()
            
            return MFAVerificationResponse(
                success=True,
                message="MFA verification successful",
                session_id=session.id
            )

    # Private helper methods
    async def _verify_user_password(self, user: User, password: str) -> bool:
        """Verify user password."""
        # This would use password service in real implementation
        return True  # Placeholder
    
    async def _store_backup_codes(self, user_id: UserId, codes: list[str]) -> None:
        """Store backup codes (hashed) for user."""
        hashed_codes = [SecurityUtils.hash_token(code) for code in codes]
        await self._cache_service.set(
            f"backup_codes:{user_id.value}",
            {"codes": hashed_codes, "used": []},
            ttl=None  # No expiry
        )
    
    async def _clear_backup_codes(self, user_id: UserId) -> None:
        """Clear backup codes for user."""
        await self._cache_service.delete(f"backup_codes:{user_id.value}")
    
    async def _verify_backup_code(self, user_id: UserId, code: str) -> bool:
        """Verify and consume backup code."""
        data = await self._cache_service.get(f"backup_codes:{user_id.value}")
        if not data:
            return False
        
        code_hash = SecurityUtils.hash_token(code)
        if code_hash in data["codes"] and code_hash not in data["used"]:
            data["used"].append(code_hash)
            await self._cache_service.set(f"backup_codes:{user_id.value}", data)
            return True
        
        return False
    
    async def _terminate_session(self, session: Session, reason: str) -> None:
        """Terminate session with reason."""
        session.terminate(reason)
        await self._session_repository.update(session)