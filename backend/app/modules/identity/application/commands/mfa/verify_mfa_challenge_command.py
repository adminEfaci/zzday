"""
Verify MFA challenge command implementation.

Handles MFA verification during authentication.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import VerifyMFAChallengeRequest
from app.modules.identity.application.dtos.response import LoginResponse
from app.modules.identity.domain.entities import MFADevice, Session
from app.modules.identity.domain.enums import (
    AuditAction,
    MFAMethod,
    RiskLevel,
    SecurityEventType,
    SessionStatus,
)
from app.modules.identity.domain.errors import InvalidOperationError
from app.modules.identity.domain.events import MFAChallengeCompleted, MFAChallengeFailed
from app.modules.identity.domain.exceptions import (
    InvalidVerificationCodeError,
    MFAChallengeExpiredError,
    MFADeviceNotFoundError,
    SessionNotFoundError,
    TooManyAttemptsError,
)
from app.modules.identity.domain.interfaces.repositories.mfa_challenge_repository import (
    IMFAChallengeRepository,
)
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import (
    IMFADeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    INotificationService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import (
    MFAService,
    SecurityService,
    SessionService,
    TokenService,
)


class VerifyMFAChallengeCommand(Command[LoginResponse]):
    """Command to verify MFA during login."""
    
    def __init__(
        self,
        session_id: UUID,
        device_id: UUID | None = None,
        code: str | None = None,
        backup_code: bool = False,
        ip_address: str | None = None,
        user_agent: str | None = None
    ):
        self.session_id = session_id
        self.device_id = device_id
        self.code = code
        self.backup_code = backup_code
        self.ip_address = ip_address
        self.user_agent = user_agent


class VerifyMFAChallengeCommandHandler(CommandHandler[VerifyMFAChallengeCommand, LoginResponse]):
    """Handler for MFA challenge verification."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        mfa_device_repository: IMFADeviceRepository,
        mfa_challenge_repository: IMFAChallengeRepository,
        mfa_service: MFAService,
        session_service: SessionService,
        token_service: TokenService,
        security_service: SecurityService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._mfa_device_repository = mfa_device_repository
        self._challenge_repository = mfa_challenge_repository
        self._mfa_service = mfa_service
        self._session_service = session_service
        self._token_service = token_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.MFA_CHALLENGE_VERIFIED,
        resource_type="session",
        resource_id_attr="session_id",
        include_request=False,  # Don't log codes
        include_errors=True
    )
    @validate_request(VerifyMFAChallengeRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=300,  # 5 minutes
        strategy='session'
    )
    async def handle(self, command: VerifyMFAChallengeCommand) -> LoginResponse:
        """
        Verify MFA challenge and complete authentication.
        
        Process:
        1. Load and validate session
        2. Check challenge status
        3. Verify code based on method
        4. Complete authentication
        5. Generate tokens
        6. Log events
        
        Returns:
            LoginResponse with authentication tokens
            
        Raises:
            SessionNotFoundError: If session not found
            MFAChallengeExpiredError: If challenge expired
            InvalidVerificationCodeError: If code invalid
            TooManyAttemptsError: If too many failed attempts
        """
        async with self._unit_of_work:
            # 1. Load MFA session
            session = await self._session_repository.find_by_id(command.session_id)
            
            if not session:
                raise SessionNotFoundError("Session not found")
            
            # 2. Validate session is pending MFA
            if session.status != SessionStatus.PENDING_MFA:
                raise InvalidOperationError(
                    f"Session is not pending MFA verification: {session.status.value}"
                )
            
            # 3. Check if session expired
            if session.expires_at < datetime.now(UTC):
                await self._handle_expired_challenge(session)
                raise MFAChallengeExpiredError("MFA challenge has expired")
            
            # 4. Load user
            user = await self._user_repository.find_by_id(session.user_id)
            
            if not user or not user.is_active:
                raise InvalidOperationError("User account is not active")
            
            # 5. Get challenge attempts
            attempts = await self._get_challenge_attempts(session.id)
            
            if attempts >= 5:
                await self._handle_too_many_attempts(session, user)
                raise TooManyAttemptsError("Too many failed MFA attempts")
            
            # 6. Verify code
            is_valid = False
            method_used = None
            
            if command.backup_code:
                # Verify backup code
                is_valid = await self._verify_backup_code(
                    user_id=user.id,
                    code=command.code
                )
                method_used = MFAMethod.BACKUP_CODES
                
            else:
                # Load specified device or primary
                device = await self._get_mfa_device(
                    user_id=user.id,
                    device_id=command.device_id
                )
                
                if not device:
                    raise MFADeviceNotFoundError("No valid MFA device found")
                
                # Verify based on device method
                is_valid = await self._verify_device_code(
                    device=device,
                    code=command.code
                )
                method_used = device.method
            
            # 7. Handle verification result
            if not is_valid:
                await self._handle_failed_verification(
                    session=session,
                    user=user,
                    command=command,
                    attempts=attempts + 1
                )
                
                raise InvalidVerificationCodeError("Invalid verification code")
            
            # 8. Complete authentication
            session.complete_mfa_verification()
            await self._session_repository.update(session)
            
            # 9. Generate tokens
            access_token = await self._token_service.generate_access_token(
                user_id=user.id,
                session_id=session.id,
                scopes=await self._get_user_scopes(user.id)
            )
            
            refresh_token = await self._token_service.generate_refresh_token(
                user_id=user.id,
                session_id=session.id
            )
            
            # 10. Update user last login
            user.record_login(
                ip_address=command.ip_address,
                user_agent=command.user_agent
            )
            await self._user_repository.update(user)
            
            # 11. Clear challenge cache
            await self._cache_service.delete(f"mfa_challenge:{session.id}")
            await self._cache_service.delete(f"mfa_attempts:{session.id}")
            
            # 12. Log successful verification
            await self._security_service.log_security_event(
                user_id=user.id,
                event_type="mfa_challenge_success",
                ip_address=command.ip_address,
                details={
                    "session_id": str(session.id),
                    "method": method_used.value if method_used else "backup_code"
                }
            )
            
            # 13. Publish event
            await self._event_bus.publish(
                MFAChallengeCompleted(
                    aggregate_id=user.id,
                    session_id=session.id,
                    method=method_used,
                    ip_address=command.ip_address
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            return LoginResponse(
                user_id=user.id,
                session_id=session.id,
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",
                expires_in=3600,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                requires_mfa=False,
                success=True,
                message="Authentication successful"
            )
    
    async def _get_challenge_attempts(self, session_id: UUID) -> int:
        """Get number of failed MFA attempts for session."""
        attempts = await self._cache_service.get(f"mfa_attempts:{session_id}")
        return int(attempts) if attempts else 0
    
    async def _get_mfa_device(
        self,
        user_id: UUID,
        device_id: UUID | None
    ) -> MFADevice | None:
        """Get MFA device for verification."""
        if device_id:
            # Get specific device
            device = await self._mfa_device_repository.find_by_id(device_id)
            
            if device and device.user_id == user_id and device.is_verified:
                return device
        
        # Get primary device
        devices = await self._mfa_device_repository.get_verified_devices(user_id)
        primary_devices = [d for d in devices if d.is_primary]
        
        if primary_devices:
            return primary_devices[0]
        
        # Return first available device
        return devices[0] if devices else None
    
    async def _verify_device_code(
        self,
        device: MFADevice,
        code: str
    ) -> bool:
        """Verify code for specific device."""
        if device.method == MFAMethod.AUTHENTICATOR_APP:
            secret = await self._mfa_service.decrypt_secret(device.secret)
            return await self._mfa_service.verify_totp(secret, code)
            
        if device.method == MFAMethod.SMS:
            # Verify against cached SMS code
            cached_code = await self._cache_service.get(
                f"mfa_sms:{device.id}:{device.user_id}"
            )
            return code == cached_code
            
        if device.method == MFAMethod.EMAIL:
            # Verify against cached email code
            cached_code = await self._cache_service.get(
                f"mfa_email:{device.id}:{device.user_id}"
            )
            return code == cached_code
            
        return False
    
    async def _verify_backup_code(
        self,
        user_id: UUID,
        code: str
    ) -> bool:
        """Verify and consume backup code."""
        # Get backup code device
        devices = await self._mfa_device_repository.get_by_user_and_method(
            user_id=user_id,
            method=MFAMethod.BACKUP_CODES
        )
        
        if not devices:
            return False
        
        device = devices[0]
        
        # Check each backup code
        for i, hashed_code in enumerate(device.backup_codes):
            if await self._mfa_service.verify_backup_code(code, hashed_code):
                # Remove used code
                device.backup_codes.pop(i)
                device.backup_codes_used += 1
                
                # Update device
                await self._mfa_device_repository.update(device)
                
                # Notify if running low on codes
                if len(device.backup_codes) <= 2:
                    await self._notify_low_backup_codes(user_id, len(device.backup_codes))
                
                return True
        
        return False
    
    async def _handle_expired_challenge(self, session: Session) -> None:
        """Handle expired MFA challenge."""
        session.expire()
        await self._session_repository.update(session)
        
        await self._security_service.log_security_event(
            user_id=session.user_id,
            event_type="mfa_challenge_expired",
            details={
                "session_id": str(session.id)
            }
        )
    
    async def _handle_failed_verification(
        self,
        session: Session,
        user: any,
        command: VerifyMFAChallengeCommand,
        attempts: int
    ) -> None:
        """Handle failed MFA verification."""
        # Increment attempts
        await self._cache_service.set(
            f"mfa_attempts:{session.id}",
            str(attempts),
            ttl=300  # 5 minutes
        )
        
        # Log failed attempt
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="mfa_challenge_failed",
            ip_address=command.ip_address,
            details={
                "session_id": str(session.id),
                "attempts": attempts,
                "method": "backup_code" if command.backup_code else "device"
            }
        )
        
        # Publish event
        await self._event_bus.publish(
            MFAChallengeFailed(
                aggregate_id=user.id,
                session_id=session.id,
                attempts=attempts,
                ip_address=command.ip_address
            )
        )
    
    async def _handle_too_many_attempts(
        self,
        session: Session,
        user: any
    ) -> None:
        """Handle too many failed MFA attempts."""
        # Revoke session
        session.revoke("Too many failed MFA attempts")
        await self._session_repository.update(session)
        
        # Log security incident
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.MFA_BRUTE_FORCE,
                severity=RiskLevel.HIGH,
                user_id=user.id,
                details={
                    "session_id": str(session.id)
                }
            )
        )
        
        # Notify user
        await self._notification_service.notify_user(
            user_id=user.id,
            message="Multiple failed MFA attempts detected",
            channel="email",
            priority="high"
        )
    
    async def _get_user_scopes(self, user_id: UUID) -> list[str]:
        """Get user permission scopes."""
        # This would typically load from permission service
        return ["user:read", "user:write", "profile:read", "profile:write"]
    
    async def _notify_low_backup_codes(
        self,
        user_id: UUID,
        remaining: int
    ) -> None:
        """Notify user about low backup codes."""
        await self._notification_service.notify_user(
            user_id=user_id,
            message=f"You have only {remaining} backup codes remaining. Generate new codes.",
            channel="email",
            priority="medium"
        )