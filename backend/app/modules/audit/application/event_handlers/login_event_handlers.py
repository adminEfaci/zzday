"""
Login Event Handlers

Handles login events (successful/failed) from the Identity module 
and creates corresponding audit trails with risk assessment and compliance tracking.
"""

from uuid import UUID

from app.core.events.handlers import EventHandler
from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.domain.enums import (
    AuditAction,
    AuditCategory,
    AuditOutcome,
    AuditSeverity,
)
from app.modules.identity.domain.entities.user.user_events import (
    AccountLockedOut,
    LoginFailed,
    LoginSuccessful,
)

logger = get_logger(__name__)


class LoginSuccessfulEventHandler(EventHandler[LoginSuccessful]):
    """Event handler for successful login events."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: LoginSuccessful) -> None:
        """Handle successful login event.
        
        Args:
            event: Login successful event
        """
        try:
            logger.info(
                "Processing login successful event",
                user_id=str(event.user_id),
                session_id=str(event.session_id),
                event_id=str(event.event_id)
            )
            
            # Determine if this is a risky login
            is_risky = self._assess_login_risk(event)
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.LOGIN,
                operation="authentication.login_success",
                description=f"User successfully logged in{' (risky login detected)' if is_risky else ''}",
                resource_type="authentication_session",
                resource_id=str(event.session_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.MEDIUM if is_risky else AuditSeverity.INFO,
                category=AuditCategory.AUTHENTICATION,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                tags=["login", "authentication", "success"] + (["risky"] if is_risky else []),
                compliance_tags=["access-audit", "authentication-log"],
                custom_fields={
                    "session_id": str(event.session_id),
                    "authentication_method": event.authentication_method,
                    "mfa_used": event.mfa_used,
                    "location": event.location,
                    "device_fingerprint": event.device_fingerprint,
                    "login_type": event.login_type,
                    "risk_score": event.risk_score,
                    "new_location": self._is_new_location(event),
                    "new_device": self._is_new_device(event)
                }
            )
            
            # Create security audit for risky logins
            if is_risky:
                await self._create_risky_login_audit(event)
            
            # Create MFA bypass audit if applicable
            if not event.mfa_used and self._should_have_mfa(event.user_id):
                await self._create_mfa_bypass_audit(event)
            
            logger.info(
                "Successfully processed login successful event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process login successful event",
                user_id=str(event.user_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_risky_login_audit(self, event: LoginSuccessful) -> None:
        """Create audit trail for risky login.
        
        Args:
            event: Login successful event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.SECURITY_ALERT,
            operation="security.risky_login_detected",
            description=f"Risky login detected with risk score {event.risk_score}",
            resource_type="security_assessment",
            resource_id=str(event.session_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.MEDIUM,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["risky-login", "security-monitoring", "anomaly-detection"],
            compliance_tags=["risk-management", "security-controls"],
            custom_fields={
                "risk_factors": self._get_risk_factors(event),
                "risk_score": event.risk_score,
                "recommended_action": "monitor_session",
                "notification_sent": True
            }
        )
    
    async def _create_mfa_bypass_audit(self, event: LoginSuccessful) -> None:
        """Create audit trail for MFA bypass.
        
        Args:
            event: Login successful event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.POLICY_VIOLATION,
            operation="security.mfa_bypassed",
            description="Login completed without MFA when MFA is recommended",
            resource_type="security_policy",
            resource_id="mfa_policy",
            outcome=AuditOutcome.WARNING,
            severity=AuditSeverity.MEDIUM,
            category=AuditCategory.COMPLIANCE,
            event_id=str(event.event_id),
            tags=["mfa-bypass", "policy-violation", "security-gap"],
            compliance_tags=["authentication-policy", "security-compliance"],
            custom_fields={
                "policy_name": "multi_factor_authentication",
                "bypass_reason": "user_choice",
                "risk_accepted": False,
                "remediation_required": True
            }
        )
    
    def _assess_login_risk(self, event: LoginSuccessful) -> bool:
        """Assess if login is risky.
        
        Args:
            event: Login successful event
            
        Returns:
            True if login is considered risky
        """
        return (event.risk_score > 0.6 or 
                self._is_new_location(event) or 
                self._is_new_device(event) or
                event.authentication_method == "emergency")
    
    def _is_new_location(self, event: LoginSuccessful) -> bool:
        """Check if login is from new location."""
        # In real implementation, would check against user's location history
        return event.location and "new" in event.location.lower()
    
    def _is_new_device(self, event: LoginSuccessful) -> bool:
        """Check if login is from new device."""
        # In real implementation, would check against user's device history
        return bool(event.device_fingerprint and not hasattr(event, 'known_device'))
    
    def _should_have_mfa(self, user_id: UUID) -> bool:
        """Check if user should have MFA enabled."""
        # In real implementation, would check user's role and policies
        return True  # Assume MFA is recommended for all users
    
    def _get_risk_factors(self, event: LoginSuccessful) -> list[str]:
        """Get list of risk factors for login."""
        factors = []
        if self._is_new_location(event):
            factors.append("new_location")
        if self._is_new_device(event):
            factors.append("new_device")
        if not event.mfa_used:
            factors.append("no_mfa")
        if event.risk_score > 0.6:
            factors.append("high_risk_score")
        return factors


class LoginFailedEventHandler(EventHandler[LoginFailed]):
    """Event handler for failed login attempts."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: LoginFailed) -> None:
        """Handle failed login event.
        
        Args:
            event: Login failed event
        """
        try:
            logger.info(
                "Processing login failed event",
                email=event.email,
                attempt_count=event.attempt_count,
                event_id=str(event.event_id)
            )
            
            # Determine severity based on attempts and risk
            severity = self._determine_severity(event)
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.LOGIN,
                operation="authentication.login_failed",
                description=f"Login attempt failed: {event.failure_reason} (attempt {event.attempt_count})",
                resource_type="authentication_attempt",
                resource_id=event.email,
                outcome=AuditOutcome.FAILURE,
                severity=severity,
                category=AuditCategory.AUTHENTICATION,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                tags=["login", "authentication", "failure", event.failure_reason],
                compliance_tags=["access-audit", "security-monitoring"],
                custom_fields={
                    "email": event.email,
                    "failure_reason": event.failure_reason,
                    "attempt_count": event.attempt_count,
                    "risk_score": event.risk_score,
                    "device_fingerprint": event.device_fingerprint,
                    "suspicious_activity": event.risk_score > 0.7,
                    "lockout_threshold": 5
                }
            )
            
            # Create security alert for multiple failures
            if event.attempt_count >= 3:
                await self._create_brute_force_alert(event)
            
            logger.info(
                "Successfully processed login failed event",
                email=event.email,
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process login failed event",
                email=event.email,
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_brute_force_alert(self, event: LoginFailed) -> None:
        """Create security alert for potential brute force attack.
        
        Args:
            event: Login failed event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.SECURITY_ALERT,
            operation="security.brute_force_detected",
            description=f"Potential brute force attack: {event.attempt_count} failed attempts",
            resource_type="security_threat",
            resource_id=event.email,
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.HIGH if event.attempt_count >= 5 else AuditSeverity.MEDIUM,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            ip_address=event.ip_address,
            tags=["brute-force", "attack-detection", "authentication-attack"],
            compliance_tags=["incident-response", "threat-detection"],
            custom_fields={
                "threat_type": "brute_force_authentication",
                "attack_vector": "password_guessing",
                "mitigation_applied": event.attempt_count >= 5,
                "ip_reputation": "unknown",  # Would check IP reputation service
                "recommended_action": "block_ip" if event.attempt_count >= 5 else "monitor"
            }
        )
    
    def _determine_severity(self, event: LoginFailed) -> AuditSeverity:
        """Determine severity based on attempts and risk.
        
        Args:
            event: Login failed event
            
        Returns:
            Appropriate severity level
        """
        if event.attempt_count >= 5 or event.risk_score > 0.8:
            return AuditSeverity.HIGH
        if event.attempt_count >= 3 or event.risk_score > 0.6:
            return AuditSeverity.MEDIUM
        return AuditSeverity.LOW


class AccountLockedOutEventHandler(EventHandler[AccountLockedOut]):
    """Event handler for account lockout events."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: AccountLockedOut) -> None:
        """Handle account locked out event.
        
        Args:
            event: Account locked out event
        """
        try:
            logger.info(
                "Processing account locked out event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.ACCOUNT_LOCKED,
                operation="security.account_lockout",
                description=f"Account locked after {event.failed_attempt_count} failed attempts",
                resource_type="user_account",
                resource_id=str(event.user_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.HIGH,
                category=AuditCategory.SECURITY,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=event.last_failed_ip,
                tags=["account-lockout", "security", "authentication-failure"],
                compliance_tags=["security-policy", "account-protection"],
                custom_fields={
                    "locked_at": event.locked_at.isoformat() if event.locked_at else None,
                    "unlock_at": event.unlock_at.isoformat() if event.unlock_at else None,
                    "lockout_duration_minutes": event.lockout_duration_minutes,
                    "failed_attempt_count": event.failed_attempt_count,
                    "last_failed_ip": event.last_failed_ip,
                    "security_action": "automatic_lockout",
                    "notification_sent": True
                }
            )
            
            # Create incident audit trail
            await self._create_security_incident_audit(event)
            
            logger.info(
                "Successfully processed account locked out event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process account locked out event",
                user_id=str(event.user_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_security_incident_audit(self, event: AccountLockedOut) -> None:
        """Create security incident audit trail.
        
        Args:
            event: Account locked out event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.SECURITY_INCIDENT,
            operation="incident.authentication_attack_mitigated",
            description="Authentication attack mitigated by account lockout",
            resource_type="security_incident",
            resource_id=f"incident_{event.user_id}_{event.locked_at}",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.HIGH,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["incident", "attack-mitigation", "account-protection"],
            compliance_tags=["incident-management", "security-response"],
            custom_fields={
                "incident_type": "authentication_attack",
                "mitigation_type": "account_lockout",
                "attack_source_ip": event.last_failed_ip,
                "response_effectiveness": "high",
                "further_action_required": "investigate_source"
            }
        )