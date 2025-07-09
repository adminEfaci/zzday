"""
MFA Challenge Event Handlers

Handles MFA challenge events (completed/failed) from the Identity module 
and creates corresponding audit trails with risk assessment.
"""


from app.core.events.handlers import EventHandler
from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.domain.enums import (
    AuditAction,
    AuditCategory,
    AuditOutcome,
    AuditSeverity,
)
from app.modules.identity.domain.events import MFAChallengeCompleted, MFAChallengeFailed

logger = get_logger(__name__)


class MFAChallengeCompletedEventHandler(EventHandler[MFAChallengeCompleted]):
    """Event handler for successful MFA challenge completion."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: MFAChallengeCompleted) -> None:
        """Handle MFA challenge completed event.
        
        Args:
            event: MFA challenge completed event
        """
        try:
            logger.info(
                "Processing MFA challenge completed event",
                session_id=str(event.session_id),
                user_id=str(event.user_id),
                method=event.method,
                event_id=str(event.event_id)
            )
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.MFA_VERIFICATION,
                operation="mfa.challenge_completed",
                description=f"MFA challenge successfully completed using {event.method}",
                resource_type="authentication_session",
                resource_id=str(event.session_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.INFO,
                category=AuditCategory.AUTHENTICATION,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=getattr(event, 'ip_address', None),
                user_agent=getattr(event, 'user_agent', None),
                tags=["mfa", "authentication", "success", event.method],
                compliance_tags=["authentication-audit", "access-control"],
                custom_fields={
                    "session_id": str(event.session_id),
                    "partial_session_id": str(event.partial_session_id),
                    "mfa_method": event.method,
                    "device_id": str(event.device_id) if event.device_id else None,
                    "completed_at": event.completed_at.isoformat() if event.completed_at else None,
                    "authentication_factor": "second_factor",
                    "authentication_strength": "strong"
                }
            )
            
            # Create security audit trail
            await self._create_security_audit_trail(event)
            
            logger.info(
                "Successfully processed MFA challenge completed event",
                session_id=str(event.session_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process MFA challenge completed event",
                session_id=str(event.session_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_security_audit_trail(self, event: MFAChallengeCompleted) -> None:
        """Create security-specific audit trail.
        
        Args:
            event: MFA challenge completed event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.ACCESS_GRANTED,
            operation="security.mfa_verification_success",
            description="Multi-factor authentication verification successful",
            resource_type="security_verification",
            resource_id=str(event.session_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.LOW,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["security-verification", "mfa-success", "access-granted"],
            custom_fields={
                "verification_method": event.method,
                "risk_assessment": "low",
                "trust_level": "high",
                "session_security": "enhanced"
            }
        )


class MFAChallengeFailedEventHandler(EventHandler[MFAChallengeFailed]):
    """Event handler for failed MFA challenge attempts."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: MFAChallengeFailed) -> None:
        """Handle MFA challenge failed event.
        
        Args:
            event: MFA challenge failed event
        """
        try:
            logger.info(
                "Processing MFA challenge failed event",
                session_id=str(event.session_id),
                user_id=str(event.user_id),
                attempt=event.attempt,
                event_id=str(event.event_id)
            )
            
            # Determine severity based on attempt count
            severity = self._determine_severity(event.attempt)
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.MFA_VERIFICATION,
                operation="mfa.challenge_failed",
                description=f"MFA challenge failed - attempt {event.attempt}: {event.reason}",
                resource_type="authentication_session",
                resource_id=str(event.session_id),
                outcome=AuditOutcome.FAILURE,
                severity=severity,
                category=AuditCategory.AUTHENTICATION,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=getattr(event, 'ip_address', None),
                user_agent=getattr(event, 'user_agent', None),
                tags=["mfa", "authentication", "failure", event.method],
                compliance_tags=["authentication-audit", "security-monitoring"],
                custom_fields={
                    "session_id": str(event.session_id),
                    "mfa_method": event.method,
                    "failure_reason": event.reason,
                    "attempt_number": event.attempt,
                    "failed_at": event.failed_at.isoformat() if event.failed_at else None,
                    "risk_indicator": "authentication_failure",
                    "requires_investigation": event.attempt >= 3
                }
            )
            
            # Create security alert if multiple failures
            if event.attempt >= 3:
                await self._create_security_alert(event)
            
            # Create potential attack audit trail if max attempts
            if event.attempt >= 5:
                await self._create_attack_audit_trail(event)
            
            logger.info(
                "Successfully processed MFA challenge failed event",
                session_id=str(event.session_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process MFA challenge failed event",
                session_id=str(event.session_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_security_alert(self, event: MFAChallengeFailed) -> None:
        """Create security alert for multiple failed attempts.
        
        Args:
            event: MFA challenge failed event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.SECURITY_ALERT,
            operation="security.mfa_multiple_failures",
            description=f"Multiple MFA verification failures detected ({event.attempt} attempts)",
            resource_type="security_alert",
            resource_id=str(event.session_id),
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.MEDIUM,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["security-alert", "mfa-failures", "suspicious-activity"],
            compliance_tags=["incident-response", "security-monitoring"],
            custom_fields={
                "alert_type": "authentication_anomaly",
                "threat_level": "medium",
                "recommended_action": "monitor_account",
                "notification_required": True
            }
        )
    
    async def _create_attack_audit_trail(self, event: MFAChallengeFailed) -> None:
        """Create potential attack audit trail.
        
        Args:
            event: MFA challenge failed event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.POTENTIAL_BREACH,
            operation="security.possible_mfa_attack",
            description="Potential MFA brute force attack detected",
            resource_type="security_incident",
            resource_id=str(event.session_id),
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.HIGH,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["security-incident", "potential-attack", "mfa-brute-force"],
            compliance_tags=["incident-response", "security-breach", "investigation-required"],
            custom_fields={
                "incident_type": "authentication_attack",
                "attack_pattern": "mfa_brute_force",
                "threat_level": "high",
                "response_required": "immediate",
                "lockout_recommended": True,
                "investigation_priority": "high"
            }
        )
    
    def _determine_severity(self, attempt: int) -> AuditSeverity:
        """Determine severity based on attempt count.
        
        Args:
            attempt: Number of failed attempts
            
        Returns:
            Appropriate severity level
        """
        if attempt >= 5:
            return AuditSeverity.HIGH
        if attempt >= 3:
            return AuditSeverity.MEDIUM
        return AuditSeverity.LOW