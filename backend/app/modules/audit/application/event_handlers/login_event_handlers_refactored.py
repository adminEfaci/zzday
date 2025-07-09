"""
Login Event Handlers (Refactored)

This is the refactored version that uses the Identity adapter
instead of direct imports from Identity's domain layer.

IMPORTANT: This demonstrates the correct pattern. The original
login_event_handlers.py should be updated to follow this pattern.
"""

from datetime import datetime
from uuid import UUID

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.domain.enums import (
    AuditAction,
    AuditCategory,
    AuditOutcome,
    AuditSeverity,
)

logger = get_logger(__name__)


class LoginEventHandlerService:
    """
    Service to handle login-related events from Identity module.
    
    This service is used by the Identity adapter to process events
    without creating circular dependencies.
    """
    
    def __init__(self, audit_service: AuditService):
        """
        Initialize the handler service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
    
    async def audit_user_login(
        self,
        user_id: UUID,
        session_id: UUID,
        ip_address: str,
        user_agent: str,
        mfa_used: bool,
        timestamp: datetime,
        correlation_id: str | None = None,
    ) -> None:
        """Handle successful login event."""
        try:
            logger.info(
                "Processing login successful event",
                user_id=str(user_id),
                session_id=str(session_id),
                correlation_id=correlation_id,
            )
            
            # Determine if this is a risky login
            is_risky = self._assess_login_risk(ip_address, user_agent)
            
            # Map severity based on risk
            severity = AuditSeverity.MEDIUM if is_risky else AuditSeverity.LOW
            
            # Additional context for the audit entry
            context = {
                "session_id": str(session_id),
                "authentication_type": "mfa" if mfa_used else "password",
                "risk_level": "high" if is_risky else "normal",
                "timestamp": timestamp.isoformat(),
            }
            
            # Create audit entry
            await self._audit_service.record_audit_entry(
                actor_id=user_id,
                action=AuditAction.LOGIN,
                resource_type="session",
                resource_id=str(session_id),
                outcome=AuditOutcome.SUCCESS,
                severity=severity,
                category=AuditCategory.AUTHENTICATION,
                ip_address=ip_address,
                user_agent=user_agent,
                context=context,
                correlation_id=correlation_id,
            )
            
            # If this is a risky login, create additional security audit
            if is_risky:
                await self._create_security_audit(
                    user_id=user_id,
                    session_id=session_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    reason="Suspicious login detected",
                    correlation_id=correlation_id,
                )
                
        except Exception as e:
            logger.exception(
                "Failed to process login successful event",
                user_id=str(user_id),
                error=str(e),
            )
    
    async def audit_login_failure(
        self,
        email: str,
        ip_address: str,
        reason: str,
        attempt_number: int,
        timestamp: datetime,
        correlation_id: str | None = None,
    ) -> None:
        """Handle failed login event."""
        try:
            logger.info(
                "Processing login failed event",
                email=email,
                attempt_number=attempt_number,
                correlation_id=correlation_id,
            )
            
            # Determine severity based on attempt count
            severity = self._determine_failure_severity(attempt_number)
            
            # Context for the audit entry
            context = {
                "email": email,
                "failure_reason": reason,
                "attempt_number": attempt_number,
                "timestamp": timestamp.isoformat(),
            }
            
            # Create audit entry - using system actor since user is not authenticated
            await self._audit_service.record_audit_entry(
                actor_id=None,  # System actor
                action=AuditAction.LOGIN_ATTEMPT,
                resource_type="authentication",
                resource_id=email,
                outcome=AuditOutcome.FAILURE,
                severity=severity,
                category=AuditCategory.AUTHENTICATION,
                ip_address=ip_address,
                context=context,
                correlation_id=correlation_id,
            )
            
            # If this is a repeated failure, create security audit
            if attempt_number >= 3:
                await self._create_security_audit(
                    user_id=None,
                    session_id=None,
                    ip_address=ip_address,
                    user_agent=None,
                    reason=f"Multiple login failures for {email} ({attempt_number} attempts)",
                    correlation_id=correlation_id,
                )
                
        except Exception as e:
            logger.exception(
                "Failed to process login failed event",
                email=email,
                error=str(e),
            )
    
    async def audit_user_lockout(
        self,
        user_id: UUID,
        locked_until: datetime,
        reason: str,
        timestamp: datetime,
        correlation_id: str | None = None,
    ) -> None:
        """Handle account lockout event."""
        try:
            logger.info(
                "Processing account locked out event",
                user_id=str(user_id),
                locked_until=locked_until.isoformat(),
                correlation_id=correlation_id,
            )
            
            # Context for the audit entry
            context = {
                "lockout_reason": reason,
                "locked_until": locked_until.isoformat(),
                "timestamp": timestamp.isoformat(),
            }
            
            # Create audit entry
            await self._audit_service.record_audit_entry(
                actor_id=user_id,
                action=AuditAction.ACCOUNT_LOCKED,
                resource_type="user_account",
                resource_id=str(user_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.HIGH,
                category=AuditCategory.SECURITY,
                context=context,
                correlation_id=correlation_id,
            )
            
            # Always create security audit for lockouts
            await self._create_security_audit(
                user_id=user_id,
                session_id=None,
                ip_address=None,
                user_agent=None,
                reason=f"Account locked: {reason}",
                correlation_id=correlation_id,
            )
            
        except Exception as e:
            logger.exception(
                "Failed to process account locked out event",
                user_id=str(user_id),
                error=str(e),
            )
    
    def _assess_login_risk(self, ip_address: str, user_agent: str) -> bool:
        """
        Assess if a login attempt is risky.
        
        In a real implementation, this would check:
        - IP reputation
        - Geolocation anomalies
        - Device fingerprinting
        - Time-based patterns
        """
        # Simplified risk assessment for demonstration
        suspicious_ips = ["10.0.0.1", "192.168.1.1"]
        suspicious_agents = ["bot", "crawler", "scanner"]
        
        if ip_address in suspicious_ips:
            return True
            
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            return True
            
        return False
    
    def _determine_failure_severity(self, attempt_number: int) -> AuditSeverity:
        """Determine severity based on number of failed attempts."""
        if attempt_number >= 5:
            return AuditSeverity.CRITICAL
        if attempt_number >= 3:
            return AuditSeverity.HIGH
        if attempt_number >= 2:
            return AuditSeverity.MEDIUM
        return AuditSeverity.LOW
    
    async def _create_security_audit(
        self,
        user_id: UUID | None,
        session_id: UUID | None,
        ip_address: str | None,
        user_agent: str | None,
        reason: str,
        correlation_id: str | None = None,
    ) -> None:
        """Create a security-related audit entry."""
        context = {
            "security_reason": reason,
            "alert_triggered": True,
        }
        
        if session_id:
            context["session_id"] = str(session_id)
            
        await self._audit_service.record_audit_entry(
            actor_id=user_id,
            action=AuditAction.SECURITY_ALERT,
            resource_type="security",
            resource_id=str(user_id) if user_id else "system",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.HIGH,
            category=AuditCategory.SECURITY,
            ip_address=ip_address,
            user_agent=user_agent,
            context=context,
            correlation_id=correlation_id,
        )