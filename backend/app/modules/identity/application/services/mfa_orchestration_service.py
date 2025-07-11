"""
MFA Orchestration Service

Coordinates Multi-Factor Authentication across different providers and methods.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice, MFAMethod
from app.modules.identity.domain.entities.session.session import Session
from app.modules.identity.domain.entities.session.session_enums import SessionStatus
from app.modules.identity.domain.events import (
    MFAChallengeCompleted,
    MFAChallengeFailed,
    MFAChallengeInitiated,
)
from app.modules.identity.domain.interfaces.repositories.session.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user.mfa_repository import (
    IMFARepository,
)
from app.modules.identity.domain.interfaces.repositories.user.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.authentication.mfa_service import (
    IMFAProvider,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort,
)
from app.modules.identity.domain.interfaces.services.infrastructure.event_publisher_port import (
    IEventPublisherPort,
)
from app.modules.identity.domain.value_objects.risk_assessment import RiskLevel
from app.modules.identity.infrastructure.services.email_mfa_provider import (
    EmailMFAProvider,
)
from app.modules.identity.infrastructure.services.sms_mfa_provider import SMSMFAProvider
from app.modules.identity.infrastructure.services.totp_service import TOTPService

logger = logging.getLogger(__name__)


class MFAOrchestrationService:
    """Service to orchestrate MFA operations across different providers."""
    
    def __init__(
        self,
        mfa_repository: IMFARepository,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        cache_port: ICachePort,
        event_publisher: IEventPublisherPort,
        totp_service: TOTPService,
        sms_provider: SMSMFAProvider,
        email_provider: EmailMFAProvider
    ):
        """Initialize MFA orchestration service.
        
        Args:
            mfa_repository: Repository for MFA devices
            user_repository: Repository for users
            session_repository: Repository for sessions
            cache_port: Cache service
            event_publisher: Event publishing service
            totp_service: TOTP authentication service
            sms_provider: SMS MFA provider
            email_provider: Email MFA provider
        """
        self.mfa_repository = mfa_repository
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.cache = cache_port
        self.event_publisher = event_publisher
        
        # Initialize providers map
        self.providers: dict[MFAMethod, IMFAProvider] = {
            MFAMethod.TOTP: totp_service,
            MFAMethod.SMS: sms_provider,
            MFAMethod.EMAIL: email_provider
        }
        
        # Challenge settings
        self.challenge_expiry_minutes = 5
        self.max_challenge_attempts = 5
    
    async def send_challenge(
        self,
        user_id: UUID,
        session_id: UUID,
        method: MFAMethod | None = None,
        device_id: UUID | None = None
    ) -> dict[str, Any]:
        """Send MFA challenge to user.
        
        Args:
            user_id: User ID
            session_id: Session ID for the challenge
            method: Specific MFA method to use (optional)
            device_id: Specific device ID to use (optional)
            
        Returns:
            Challenge information including method and expiry
        """
        # Get user
        user = await self.user_repository.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Get available MFA devices
        devices = await self.mfa_repository.find_verified_by_user(user_id)
        if not devices:
            raise ValueError("No verified MFA devices found")
        
        # Select device
        device = self._select_device(devices, method, device_id)
        if not device:
            raise ValueError("No suitable MFA device found")
        
        # Get provider
        provider = self.providers.get(device.method)
        if not provider:
            raise ValueError(f"MFA provider not available for method: {device.method}")
        
        # Check provider availability
        if not await provider.is_available():
            raise ValueError(f"MFA provider {device.method} is currently unavailable")
        
        # Create challenge ID
        challenge_id = f"mfa_challenge:{session_id}"
        
        # Send challenge based on method
        result = {}
        if device.method == MFAMethod.TOTP:
            # TOTP doesn't send anything, just prepare for verification
            result = {
                "sent": True,
                "message": "Enter code from your authenticator app"
            }
        else:
            # Send code via SMS/Email
            result = await provider.send_code(device, user.email.value)
        
        # Cache challenge information
        challenge_data = {
            "user_id": str(user_id),
            "session_id": str(session_id),
            "device_id": str(device.id),
            "method": device.method.value,
            "attempts": 0,
            "created_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(minutes=self.challenge_expiry_minutes)).isoformat()
        }
        
        await self.cache.set(
            challenge_id,
            challenge_data,
            ttl=self.challenge_expiry_minutes * 60
        )
        
        # Publish event
        await self.event_publisher.publish(
            MFAChallengeInitiated(
                aggregate_id=user_id,
                session_id=session_id,
                method=device.method,
                device_id=device.id,
                expires_at=datetime.now(UTC) + timedelta(minutes=self.challenge_expiry_minutes)
            )
        )
        
        logger.info(f"MFA challenge sent for user {user_id} using {device.method}")
        
        return {
            "challenge_id": challenge_id,
            "method": device.method.value,
            "device_name": device.device_name,
            "expires_in_seconds": self.challenge_expiry_minutes * 60,
            **result
        }
    
    async def verify_challenge(
        self,
        session_id: UUID,
        code: str,
        device_id: UUID | None = None
    ) -> tuple[bool, dict[str, Any]]:
        """Verify MFA challenge code.
        
        Args:
            session_id: Session ID
            code: Verification code
            device_id: Optional device ID to verify against
            
        Returns:
            Tuple of (is_valid, metadata)
        """
        challenge_id = f"mfa_challenge:{session_id}"
        
        # Get challenge data
        challenge_data = await self.cache.get(challenge_id)
        if not challenge_data:
            return False, {"error": "Challenge not found or expired"}
        
        # Check expiry
        expires_at = datetime.fromisoformat(challenge_data["expires_at"])
        if datetime.now(UTC) > expires_at:
            await self.cache.delete(challenge_id)
            return False, {"error": "Challenge expired"}
        
        # Check attempts
        attempts = challenge_data.get("attempts", 0)
        if attempts >= self.max_challenge_attempts:
            await self.cache.delete(challenge_id)
            return False, {"error": "Too many failed attempts"}
        
        # Get device
        stored_device_id = UUID(challenge_data["device_id"])
        if device_id and device_id != stored_device_id:
            return False, {"error": "Device mismatch"}
        
        device = await self.mfa_repository.find_by_id(stored_device_id)
        if not device:
            return False, {"error": "MFA device not found"}
        
        # Get provider
        provider = self.providers.get(device.method)
        if not provider:
            return False, {"error": "MFA provider not available"}
        
        # Verify code
        is_valid, verify_metadata = await provider.verify_code(device, code)
        
        if is_valid:
            # Clear challenge
            await self.cache.delete(challenge_id)
            
            # Update device last used
            await self.mfa_repository.update_last_used(device.id)
            
            # Publish success event
            await self.event_publisher.publish(
                MFAChallengeCompleted(
                    aggregate_id=UUID(challenge_data["user_id"]),
                    session_id=session_id,
                    method=device.method,
                    device_id=device.id
                )
            )
            
            logger.info(f"MFA challenge verified for session {session_id}")
            
            return True, {
                "method": device.method.value,
                "device_id": str(device.id),
                **verify_metadata
            }
        # Increment attempts
        challenge_data["attempts"] = attempts + 1
        await self.cache.set(
            challenge_id,
            challenge_data,
            ttl=self.challenge_expiry_minutes * 60
        )
        
        # Publish failure event
        await self.event_publisher.publish(
            MFAChallengeFailed(
                aggregate_id=UUID(challenge_data["user_id"]),
                session_id=session_id,
                attempts=challenge_data["attempts"],
                reason=verify_metadata.get("error", "Invalid code")
            )
        )
        
        remaining_attempts = self.max_challenge_attempts - challenge_data["attempts"]
        logger.warning(f"MFA challenge failed for session {session_id}, {remaining_attempts} attempts remaining")
        
        return False, {
            "error": verify_metadata.get("error", "Invalid code"),
            "remaining_attempts": remaining_attempts
        }
    
    async def get_available_methods(self, user_id: UUID) -> list[dict[str, Any]]:
        """Get available MFA methods for user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of available MFA methods with device information
        """
        devices = await self.mfa_repository.find_verified_by_user(user_id)
        
        methods = []
        for device in devices:
            provider = self.providers.get(device.method)
            is_available = await provider.is_available() if provider else False
            
            methods.append({
                "device_id": str(device.id),
                "method": device.method.value,
                "device_name": device.device_name,
                "is_primary": device.is_primary,
                "is_available": is_available,
                "last_used_at": device.last_used_at.isoformat() if device.last_used_at else None
            })
        
        # Sort by primary first, then by last used
        methods.sort(key=lambda x: (not x["is_primary"], x["last_used_at"] or ""), reverse=False)
        
        return methods
    
    async def select_best_method(
        self,
        user_id: UUID,
        risk_level: RiskLevel | None = None
    ) -> MFAMethod | None:
        """Select best MFA method based on user preferences and risk level.
        
        Args:
            user_id: User ID
            risk_level: Current risk assessment level
            
        Returns:
            Best MFA method to use, or None if no methods available
        """
        devices = await self.mfa_repository.find_verified_by_user(user_id)
        if not devices:
            return None
        
        # Filter by available providers
        available_devices = []
        for device in devices:
            provider = self.providers.get(device.method)
            if provider and await provider.is_available():
                available_devices.append(device)
        
        if not available_devices:
            return None
        
        # High risk requires stronger methods
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Prefer TOTP over SMS/Email for high risk
            totp_devices = [d for d in available_devices if d.method == MFAMethod.TOTP]
            if totp_devices:
                return MFAMethod.TOTP
        
        # Check for primary device
        primary_devices = [d for d in available_devices if d.is_primary]
        if primary_devices:
            return primary_devices[0].method
        
        # Use most recently used device
        available_devices.sort(key=lambda d: d.last_used_at or datetime.min, reverse=True)
        return available_devices[0].method
    
    async def create_mfa_session(
        self,
        user_id: UUID,
        session: Session,
        method: MFAMethod | None = None
    ) -> dict[str, Any]:
        """Create MFA session for authentication flow.
        
        Args:
            user_id: User ID
            session: Current session
            method: Preferred MFA method
            
        Returns:
            MFA session information
        """
        # Update session status to pending MFA
        session.status = SessionStatus.PENDING_MFA
        session.metadata["mfa_required"] = True
        session.metadata["mfa_initiated_at"] = datetime.now(UTC).isoformat()
        
        await self.session_repository.save(session)
        
        # Select method if not provided
        if not method:
            method = await self.select_best_method(user_id)
            if not method:
                raise ValueError("No MFA methods available")
        
        # Send challenge
        challenge_info = await self.send_challenge(
            user_id=user_id,
            session_id=session.id,
            method=method
        )
        
        return {
            "session_id": str(session.id),
            "mfa_required": True,
            **challenge_info
        }
    
    async def complete_mfa_verification(
        self,
        session_id: UUID,
        user_id: UUID
    ) -> None:
        """Complete MFA verification and update session.
        
        Args:
            session_id: Session ID
            user_id: User ID
        """
        # Update session
        session = await self.session_repository.find_by_id(session_id)
        if not session:
            raise ValueError("Session not found")
        
        session.status = SessionStatus.ACTIVE
        session.mfa_completed = True
        session.metadata["mfa_completed_at"] = datetime.now(UTC).isoformat()
        
        await self.session_repository.save(session)
        
        logger.info(f"MFA verification completed for user {user_id}, session {session_id}")
    
    def _select_device(
        self,
        devices: list[MFADevice],
        method: MFAMethod | None,
        device_id: UUID | None
    ) -> MFADevice | None:
        """Select appropriate MFA device.
        
        Args:
            devices: Available devices
            method: Preferred method
            device_id: Specific device ID
            
        Returns:
            Selected device or None
        """
        # Specific device requested
        if device_id:
            for device in devices:
                if device.id == device_id and device.is_verified:
                    return device
            return None
        
        # Specific method requested
        if method:
            method_devices = [d for d in devices if d.method == method and d.is_verified]
            if method_devices:
                # Prefer primary device
                primary = [d for d in method_devices if d.is_primary]
                if primary:
                    return primary[0]
                # Return most recently used
                method_devices.sort(key=lambda d: d.last_used_at or datetime.min, reverse=True)
                return method_devices[0]
            return None
        
        # No preference - return primary or most recently used
        primary = [d for d in devices if d.is_primary and d.is_verified]
        if primary:
            return primary[0]
        
        verified = [d for d in devices if d.is_verified]
        if verified:
            verified.sort(key=lambda d: d.last_used_at or datetime.min, reverse=True)
            return verified[0]
        
        return None