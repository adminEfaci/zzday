"""
Session Management Service

Service for managing session lifecycle including MFA flows.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import DomainError, NotFoundError, ValidationError
from app.modules.identity.domain.entities.session.partial_session import PartialSession
from app.modules.identity.domain.entities.session.session import Session
from app.modules.identity.domain.entities.session.session_enums import SessionStatus, SessionType
from app.modules.identity.domain.entities.admin.mfa_device import MFADevice
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.events import (
    SessionCreated,
    SessionTerminated,
    MFAChallengeIssued,
    MFAChallengeCompleted,
    MFAChallengeFailed
)
from app.modules.identity.domain.interfaces.services.authentication.token_generator import ITokenGenerator
from app.modules.identity.domain.value_objects.ip_address import IpAddress
from app.modules.identity.domain.value_objects.user_agent import UserAgent
from app.modules.identity.domain.value_objects.device_fingerprint import DeviceFingerprint
from app.modules.identity.infrastructure.services.mfa_provider_factory import MFAProviderFactory
from app.core.events.bus import IEventBus

logger = logging.getLogger(__name__)


class SessionManagementService:
    """Service for managing session lifecycle."""
    
    def __init__(
        self,
        mfa_provider_factory: MFAProviderFactory,
        token_generator: ITokenGenerator,
        event_bus: IEventBus,
        config: dict[str, Any] | None = None
    ):
        """Initialize session management service.
        
        Args:
            mfa_provider_factory: Factory for MFA providers
            token_generator: Token generation service
            event_bus: Event bus for domain events
            config: Service configuration
        """
        self.mfa_provider_factory = mfa_provider_factory
        self.token_generator = token_generator
        self.event_bus = event_bus
        self.config = config or {}
        
        # In-memory storage for partial sessions (should use cache in production)
        self._partial_sessions: dict[UUID, PartialSession] = {}
        
        # Session configuration
        self.mfa_grace_period_minutes = self.config.get('mfa_grace_period_minutes', 15)
        self.max_concurrent_sessions = self.config.get('max_concurrent_sessions', 5)
        self.session_idle_timeout_minutes = self.config.get('session_idle_timeout_minutes', 30)
    
    async def initiate_mfa_session(
        self,
        user_id: UUID,
        session_type: SessionType,
        mfa_method: MFAMethod,
        mfa_device_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_fingerprint: str | None = None,
        auth_metadata: dict[str, Any] | None = None,
        risk_score: float = 0.0
    ) -> dict[str, Any]:
        """Initiate MFA session after initial authentication.
        
        Args:
            user_id: User identifier
            session_type: Type of session
            mfa_method: MFA method to use
            mfa_device_id: Optional specific MFA device
            ip_address: Client IP address
            user_agent: Client user agent
            device_fingerprint: Device fingerprint
            auth_metadata: Authentication metadata
            risk_score: Calculated risk score
            
        Returns:
            MFA challenge information
        """
        # Create value objects
        ip_obj = IpAddress(ip_address) if ip_address else None
        ua_obj = UserAgent(user_agent) if user_agent else None
        fp_obj = DeviceFingerprint(device_fingerprint) if device_fingerprint else None
        
        # Create partial session
        partial_session = PartialSession.create_from_auth(
            user_id=user_id,
            session_type=session_type,
            mfa_method=mfa_method,
            mfa_device_id=mfa_device_id,
            ip_address=ip_obj,
            user_agent=ua_obj,
            device_fingerprint=fp_obj,
            auth_method=auth_metadata.get('auth_method', 'password') if auth_metadata else 'password',
            auth_metadata=auth_metadata or {},
            risk_score=risk_score
        )
        
        # Store partial session
        self._partial_sessions[partial_session.id] = partial_session
        
        # Get MFA provider
        provider = self.mfa_provider_factory.create_provider(mfa_method)
        
        # Send MFA challenge if applicable
        challenge_sent = False
        send_result = {}
        
        if mfa_method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            # These methods require sending a code
            # Note: In real implementation, would need to get device from repository
            mock_device = MFADevice(
                id=mfa_device_id or partial_session.id,
                user_id=user_id,
                method=mfa_method,
                device_name=f"{mfa_method.value}_device",
                secret="",
                verified=True
            )
            
            try:
                send_result = await provider.send_code(
                    device=mock_device,
                    user_identifier=str(user_id)
                )
                challenge_sent = True
            except Exception as e:
                logger.error(f"Failed to send MFA code: {e}")
                raise DomainError(f"Failed to send {mfa_method.value} code")
        
        # Emit MFA challenge event
        await self.event_bus.publish(MFAChallengeIssued(
            session_id=partial_session.id,
            user_id=user_id,
            method=mfa_method.value,
            device_id=mfa_device_id,
            issued_at=datetime.now(UTC)
        ))
        
        # Return challenge information
        challenge_info = partial_session.get_challenge_info()
        
        if challenge_sent:
            challenge_info.update(send_result)
        
        challenge_info['instructions'] = self._get_mfa_instructions(mfa_method)
        
        return challenge_info
    
    async def complete_mfa_challenge(
        self,
        session_id: UUID,
        code: str,
        device_id: UUID | None = None
    ) -> dict[str, Any]:
        """Complete MFA challenge and create full session.
        
        Args:
            session_id: Partial session ID
            code: MFA verification code
            device_id: Optional MFA device ID
            
        Returns:
            Full session information with tokens
            
        Raises:
            NotFoundError: If session not found
            ValidationError: If challenge invalid
            DomainError: If MFA verification fails
        """
        # Get partial session
        partial_session = self._partial_sessions.get(session_id)
        if not partial_session:
            raise NotFoundError("MFA session not found or expired")
        
        # Validate session state
        if partial_session.is_expired:
            del self._partial_sessions[session_id]
            raise ValidationError("MFA session has expired")
        
        if not partial_session.can_attempt_challenge:
            raise ValidationError("Maximum MFA attempts exceeded")
        
        # Record attempt
        partial_session.record_challenge_attempt()
        
        # Get MFA provider
        provider = self.mfa_provider_factory.create_provider(partial_session.mfa_method)
        
        # Verify code
        # Note: In real implementation, would get actual device from repository
        mock_device = MFADevice(
            id=device_id or partial_session.mfa_device_id or session_id,
            user_id=partial_session.user_id,
            method=partial_session.mfa_method,
            device_name=f"{partial_session.mfa_method.value}_device",
            secret="",
            verified=True
        )
        
        try:
            is_valid, verification_metadata = await provider.verify_code(
                device=mock_device,
                code=code
            )
        except Exception as e:
            logger.error(f"MFA verification error: {e}")
            is_valid = False
            verification_metadata = {'error': str(e)}
        
        if not is_valid:
            # Emit failure event
            await self.event_bus.publish(MFAChallengeFailed(
                session_id=session_id,
                user_id=partial_session.user_id,
                method=partial_session.mfa_method.value,
                attempt=partial_session.challenge_attempts,
                reason=verification_metadata.get('error', 'Invalid code'),
                failed_at=datetime.now(UTC)
            ))
            
            # Check if more attempts allowed
            if not partial_session.can_attempt_challenge:
                del self._partial_sessions[session_id]
                raise DomainError("MFA verification failed - maximum attempts exceeded")
            
            raise ValidationError(
                f"Invalid MFA code. {partial_session.max_challenge_attempts - partial_session.challenge_attempts} attempts remaining"
            )
        
        # MFA successful - create full session
        session_context = partial_session.to_session_context()
        
        # Create session with MFA completed
        session = Session.create_new(
            user_id=session_context['user_id'],
            session_type=session_context['session_type'],
            ip_address=session_context.get('ip_address'),
            user_agent=session_context.get('user_agent'),
            device_fingerprint=session_context.get('device_fingerprint'),
            requires_mfa=True,
            metadata=session_context.get('metadata', {})
        )
        
        # Mark MFA as completed
        session.complete_mfa()
        
        # Update risk score from partial session
        session.risk_score = partial_session.risk_score
        
        # Emit success event
        await self.event_bus.publish(MFAChallengeCompleted(
            session_id=session.id,
            partial_session_id=session_id,
            user_id=session.user_id,
            method=partial_session.mfa_method.value,
            device_id=device_id or partial_session.mfa_device_id,
            completed_at=datetime.now(UTC)
        ))
        
        # Emit session created event
        await self.event_bus.publish(SessionCreated(
            session_id=session.id,
            user_id=session.user_id,
            session_type=session.session_type.value,
            ip_address=str(session.ip_address) if session.ip_address else None,
            user_agent=session.user_agent.value if session.user_agent else None,
            created_at=session.created_at
        ))
        
        # Clean up partial session
        del self._partial_sessions[session_id]
        
        # Return session info with tokens
        return {
            'session_id': str(session.id),
            'user_id': str(session.user_id),
            'access_token': session.access_token.value,
            'refresh_token': session.refresh_token.value if session.refresh_token else None,
            'session_type': session.session_type.value,
            'expires_at': (session.created_at + timedelta(hours=8)).isoformat(),
            'mfa_completed': session.mfa_completed,
            'is_trusted': session.is_trusted
        }
    
    async def refresh_mfa_challenge(self, session_id: UUID) -> dict[str, Any]:
        """Refresh MFA challenge for partial session.
        
        Args:
            session_id: Partial session ID
            
        Returns:
            New challenge information
            
        Raises:
            NotFoundError: If session not found
            ValidationError: If session expired
        """
        # Get partial session
        partial_session = self._partial_sessions.get(session_id)
        if not partial_session:
            raise NotFoundError("MFA session not found")
        
        if partial_session.is_expired:
            del self._partial_sessions[session_id]
            raise ValidationError("MFA session has expired")
        
        # Refresh challenge
        partial_session.refresh_challenge()
        
        # Get provider and resend if applicable
        provider = self.mfa_provider_factory.create_provider(partial_session.mfa_method)
        
        send_result = {}
        if partial_session.mfa_method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            # Resend code
            mock_device = MFADevice(
                id=partial_session.mfa_device_id or session_id,
                user_id=partial_session.user_id,
                method=partial_session.mfa_method,
                device_name=f"{partial_session.mfa_method.value}_device",
                secret="",
                verified=True
            )
            
            try:
                send_result = await provider.send_code(
                    device=mock_device,
                    user_identifier=str(partial_session.user_id)
                )
            except Exception as e:
                logger.error(f"Failed to resend MFA code: {e}")
                raise DomainError(f"Failed to resend {partial_session.mfa_method.value} code")
        
        # Return updated challenge info
        challenge_info = partial_session.get_challenge_info()
        challenge_info.update(send_result)
        
        return challenge_info
    
    async def cancel_mfa_challenge(self, session_id: UUID) -> None:
        """Cancel MFA challenge and clean up partial session.
        
        Args:
            session_id: Partial session ID
        """
        if session_id in self._partial_sessions:
            del self._partial_sessions[session_id]
            logger.info(f"MFA challenge cancelled for session {session_id}")
    
    async def upgrade_session_after_mfa(
        self,
        session: Session,
        mfa_method: MFAMethod,
        device_id: UUID | None = None
    ) -> Session:
        """Upgrade existing session after MFA completion.
        
        Args:
            session: Existing session
            mfa_method: MFA method used
            device_id: MFA device ID
            
        Returns:
            Updated session
        """
        # Complete MFA on session
        session.complete_mfa()
        
        # Add MFA metadata
        session.metadata['mfa_method'] = mfa_method.value
        if device_id:
            session.metadata['mfa_device_id'] = str(device_id)
        session.metadata['mfa_completed_at'] = datetime.now(UTC).isoformat()
        
        # Reduce risk score after successful MFA
        session.risk_score = max(0, session.risk_score - 0.3)
        
        # Mark as trusted if using secure MFA
        if mfa_method.is_secure:
            session.is_trusted = True
        
        return session
    
    def _get_mfa_instructions(self, method: MFAMethod) -> str:
        """Get user-friendly MFA instructions.
        
        Args:
            method: MFA method
            
        Returns:
            Instructions text
        """
        instructions = {
            MFAMethod.TOTP: "Enter the 6-digit code from your authenticator app",
            MFAMethod.SMS: "Enter the verification code sent to your phone",
            MFAMethod.EMAIL: "Enter the verification code sent to your email",
            MFAMethod.HARDWARE_KEY: "Insert your security key and follow the prompts",
            MFAMethod.BACKUP_CODE: "Enter one of your backup recovery codes",
            MFAMethod.PUSH_NOTIFICATION: "Check your mobile device for the authentication request",
            MFAMethod.BIOMETRIC: "Use your registered biometric authentication"
        }
        
        return instructions.get(method, "Complete the authentication challenge")
    
    async def cleanup_expired_partial_sessions(self) -> int:
        """Clean up expired partial sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        expired = []
        now = datetime.now(UTC)
        
        for session_id, session in self._partial_sessions.items():
            if session.expires_at < now:
                expired.append(session_id)
        
        for session_id in expired:
            del self._partial_sessions[session_id]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired partial sessions")
        
        return len(expired)
    
    def get_partial_session_stats(self) -> dict[str, Any]:
        """Get statistics about partial sessions.
        
        Returns:
            Statistics dictionary
        """
        total = len(self._partial_sessions)
        by_method = {}
        expired = 0
        
        now = datetime.now(UTC)
        
        for session in self._partial_sessions.values():
            method = session.mfa_method.value
            by_method[method] = by_method.get(method, 0) + 1
            
            if session.expires_at < now:
                expired += 1
        
        return {
            'total': total,
            'active': total - expired,
            'expired': expired,
            'by_method': by_method
        }