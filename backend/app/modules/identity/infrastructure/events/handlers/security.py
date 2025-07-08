"""
Security Event Handlers

Concrete implementations for handling security-related events
in the identity domain, including threat detection, compliance logging,
and security alerting.
"""

import asyncio
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.entities.admin.admin_events import (
    ComplianceViolationDetected,
    IPBlocklisted,
    SecurityAlertRaised,
    SuspiciousActivityDetected,
)
from app.modules.identity.domain.entities.user.user_events import (
    AccountLockedOut,
    LoginFailed,
)

from .base import (
    EventHandlerBase,
    HandlerExecutionContext,
    HandlerPriority,
    HandlerResult,
    event_handler,
)

logger = get_logger(__name__)


@event_handler(
    event_types=[
        "SecurityAlertRaised",
        "SuspiciousActivityDetected",
        "LoginFailed",
        "AccountLockedOut",
        "IPBlocklisted",
        "ComplianceViolationDetected"
    ],
    priority=HandlerPriority.CRITICAL,
    category="security",
    timeout_seconds=60.0,
    tags=["security", "threat_detection", "alerting", "critical"]
)
class SecurityEventHandler(EventHandlerBase):
    """
    Handler for security-related events.
    
    Processes security events to:
    - Detect and respond to threats
    - Trigger security alerts and notifications
    - Implement automatic security responses
    - Coordinate incident response workflows
    - Update threat intelligence databases
    - Notify security operations center
    
    This is a critical security handler that must succeed for proper threat response.
    """
    
    async def handle(self, event, context: HandlerExecutionContext) -> HandlerResult:
        """Handle security events."""
        try:
            event_type = event.__class__.__name__
            tasks_completed = []
            threat_level = "low"
            
            # Process based on event type
            if event_type == "SecurityAlertRaised":
                threat_level = await self._handle_security_alert(event)
                tasks_completed.append("security_alert_processed")
            
            elif event_type == "SuspiciousActivityDetected":
                threat_level = await self._handle_suspicious_activity(event)
                tasks_completed.append("suspicious_activity_processed")
            
            elif event_type == "LoginFailed":
                threat_level = await self._handle_failed_login(event)
                tasks_completed.append("failed_login_processed")
            
            elif event_type == "AccountLockedOut":
                threat_level = await self._handle_account_lockout(event)
                tasks_completed.append("account_lockout_processed")
            
            elif event_type == "IPBlocklisted":
                threat_level = await self._handle_ip_blocklist(event)
                tasks_completed.append("ip_blocklist_processed")
            
            elif event_type == "ComplianceViolationDetected":
                threat_level = await self._handle_compliance_violation(event)
                tasks_completed.append("compliance_violation_processed")
            
            # Common security processing
            await self._update_threat_intelligence(event, threat_level)
            tasks_completed.append("threat_intelligence_updated")
            
            # Trigger automated responses if high threat
            if threat_level in ["high", "critical"]:
                await self._trigger_automated_response(event, threat_level)
                tasks_completed.append("automated_response_triggered")
            
            # Notify security operations center
            await self._notify_security_operations(event, threat_level)
            tasks_completed.append("security_operations_notified")
            
            # Log security metrics
            await self._log_security_metrics(event, threat_level)
            tasks_completed.append("security_metrics_logged")
            
            logger.warning(
                f"Security event processed: {event_type}",
                event_type=event_type,
                event_id=str(event.event_id),
                threat_level=threat_level,
                tasks_completed=tasks_completed
            )
            
            return HandlerResult(
                success=True,
                handler_id=self.metadata.handler_id,
                execution_id=context.execution_id,
                started_at=context.started_at,
                result_data={
                    "event_type": event_type,
                    "threat_level": threat_level,
                    "tasks_completed": tasks_completed,
                    "automated_response_triggered": threat_level in ["high", "critical"]
                }
            )
            
        except Exception as e:
            logger.exception(
                f"Failed to process security event {event.__class__.__name__}",
                event_type=event.__class__.__name__,
                event_id=str(event.event_id)
            )
            
            return HandlerResult(
                success=False,
                handler_id=self.metadata.handler_id,
                execution_id=context.execution_id,
                started_at=context.started_at,
                error=e,
                error_message=str(e),
                error_type=type(e).__name__
            )
    
    async def _handle_security_alert(self, event: SecurityAlertRaised) -> str:
        """Handle security alert raised event."""
        # TODO: Integrate with security alert system
        await asyncio.sleep(0.1)  # Simulate processing
        
        threat_level = event.risk_level.lower()
        
        logger.critical(
            f"Security alert: {event.alert_type}",
            alert_type=event.alert_type,
            risk_level=event.risk_level,
            description=event.description,
            source_ip=event.source_ip,
            user_id=str(event.user_id) if event.user_id else None
        )
        
        return threat_level
    
    async def _handle_suspicious_activity(self, event: SuspiciousActivityDetected) -> str:
        """Handle suspicious activity detection."""
        # TODO: Integrate with threat analysis system
        await asyncio.sleep(0.05)  # Simulate analysis
        
        # Determine threat level based on confidence and risk score
        if event.risk_score > 0.8 and event.confidence_score > 0.9:
            threat_level = "critical"
        elif event.risk_score > 0.6:
            threat_level = "high"
        elif event.risk_score > 0.3:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        logger.warning(
            f"Suspicious activity detected: {event.activity_type}",
            activity_type=event.activity_type,
            risk_score=event.risk_score,
            confidence_score=event.confidence_score,
            patterns=event.patterns_detected,
            ip_address=event.ip_address,
            user_id=str(event.user_id) if event.user_id else None,
            threat_level=threat_level
        )
        
        return threat_level
    
    async def _handle_failed_login(self, event: LoginFailed) -> str:
        """Handle failed login attempt."""
        # TODO: Integrate with brute force detection
        await asyncio.sleep(0.02)  # Simulate processing
        
        # Analyze failure pattern
        threat_level = "low"
        if event.risk_score > 0.7:
            threat_level = "high"
        elif event.risk_score > 0.4:
            threat_level = "medium"
        
        logger.warning(
            f"Failed login attempt for {event.email}",
            email=event.email,
            ip_address=event.ip_address,
            failure_reason=event.failure_reason,
            risk_score=event.risk_score,
            threat_level=threat_level
        )
        
        return threat_level
    
    async def _handle_account_lockout(self, event: AccountLockedOut) -> str:
        """Handle account lockout event."""
        # TODO: Integrate with attack detection system
        await asyncio.sleep(0.03)  # Simulate processing
        
        threat_level = "medium"  # Account lockouts are always medium threat
        
        logger.warning(
            f"Account locked out for user {event.user_id}",
            user_id=str(event.user_id),
            failed_attempts=event.failed_attempt_count,
            lockout_duration=event.lockout_duration_minutes,
            last_failed_ip=event.last_failed_ip,
            threat_level=threat_level
        )
        
        return threat_level
    
    async def _handle_ip_blocklist(self, event: IPBlocklisted) -> str:
        """Handle IP blocklist event."""
        # TODO: Integrate with network security system
        await asyncio.sleep(0.02)  # Simulate processing
        
        threat_level = event.threat_level.lower() if hasattr(event, 'threat_level') else "medium"
        
        logger.warning(
            f"IP address blocklisted: {event.ip_address}",
            ip_address=event.ip_address,
            reason=event.reason,
            threat_level=threat_level,
            blocklisted_by=str(event.blocklisted_by),
            expires_at=event.expires_at.isoformat() if event.expires_at else None
        )
        
        return threat_level
    
    async def _handle_compliance_violation(self, event: ComplianceViolationDetected) -> str:
        """Handle compliance violation event."""
        # TODO: Integrate with compliance system
        await asyncio.sleep(0.05)  # Simulate processing
        
        # Map severity to threat level
        severity_threat_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        
        threat_level = severity_threat_map.get(event.severity.lower(), "medium")
        
        logger.error(
            f"Compliance violation detected: {event.violation_type}",
            violation_type=event.violation_type,
            severity=event.severity,
            regulation=event.regulation,
            description=event.description,
            user_id=str(event.user_id) if event.user_id else None,
            threat_level=threat_level
        )
        
        return threat_level
    
    async def _update_threat_intelligence(self, event, threat_level: str) -> None:
        """Update threat intelligence database."""
        # TODO: Integrate with threat intelligence platform
        await asyncio.sleep(0.03)  # Simulate update
        
        logger.debug(
            "Threat intelligence updated",
            event_type=event.__class__.__name__,
            threat_level=threat_level
        )
    
    async def _trigger_automated_response(self, event, threat_level: str) -> None:
        """Trigger automated security responses."""
        # TODO: Integrate with security orchestration platform
        await asyncio.sleep(0.1)  # Simulate response triggering
        
        logger.critical(
            f"Automated security response triggered for {threat_level} threat",
            event_type=event.__class__.__name__,
            threat_level=threat_level
        )
    
    async def _notify_security_operations(self, event, threat_level: str) -> None:
        """Notify security operations center."""
        # TODO: Integrate with SOC notification system
        await asyncio.sleep(0.05)  # Simulate notification
        
        logger.info(
            "Security operations notified",
            event_type=event.__class__.__name__,
            threat_level=threat_level
        )
    
    async def _log_security_metrics(self, event, threat_level: str) -> None:
        """Log security metrics for monitoring."""
        # TODO: Integrate with security metrics system
        await asyncio.sleep(0.01)  # Simulate logging
        
        logger.debug(
            "Security metrics logged",
            event_type=event.__class__.__name__,
            threat_level=threat_level
        )


@event_handler(
    event_types=[
        # User lifecycle events
        "UserCreated", "UserActivated", "UserSuspended", "UserDeactivated", "UserDeleted",
        # Authentication events
        "LoginSuccessful", "LoginFailed", "AccountLockedOut", "AccountUnlocked",
        # Password events
        "PasswordChanged", "PasswordResetRequested",
        # MFA events
        "MFAEnabled", "MFADisabled",
        # Session events
        "SessionCreated", "SessionRevoked", "TokenRefreshed",
        # Security events
        "SecurityAlertRaised", "SuspiciousActivityDetected",
        # Admin events
        "IPBlocklisted", "IPAllowlisted", "ComplianceViolationDetected",
    ],
    priority=HandlerPriority.HIGH,
    category="compliance",
    timeout_seconds=30.0,
    requires_transaction=True,
    tags=["audit", "compliance", "logging", "required"]
)
class AuditLogHandler(EventHandlerBase):
    """
    Handler for audit logging of all identity events.
    
    Creates comprehensive audit trails for:
    - User lifecycle events
    - Authentication and authorization events
    - Security events and violations
    - Administrative actions
    - Compliance-related activities
    
    This handler ensures compliance with regulatory requirements
    and provides forensic capabilities for security investigations.
    """
    
    async def handle(self, event, context: HandlerExecutionContext) -> HandlerResult:
        """Handle audit logging for all events."""
        try:
            event_type = event.__class__.__name__
            
            # Create audit log entry
            audit_entry = await self._create_audit_entry(event, context)
            
            # Store in audit database
            audit_id = await self._store_audit_entry(audit_entry)
            
            # Index for search if needed
            await self._index_audit_entry(audit_entry, audit_id)
            
            # Update compliance metrics
            await self._update_compliance_metrics(event_type, audit_entry)
            
            # Check for retention policies
            await self._apply_retention_policies(event_type)
            
            logger.debug(
                f"Audit log created for {event_type}",
                event_type=event_type,
                event_id=str(event.event_id),
                audit_id=audit_id,
                user_id=audit_entry.get("user_id"),
                action=audit_entry.get("action")
            )
            
            return HandlerResult(
                success=True,
                handler_id=self.metadata.handler_id,
                execution_id=context.execution_id,
                started_at=context.started_at,
                result_data={
                    "audit_id": audit_id,
                    "event_type": event_type,
                    "audit_action": audit_entry.get("action"),
                    "indexed": True
                }
            )
            
        except Exception as e:
            logger.exception(
                f"Failed to create audit log for {event.__class__.__name__}",
                event_type=event.__class__.__name__,
                event_id=str(event.event_id)
            )
            
            return HandlerResult(
                success=False,
                handler_id=self.metadata.handler_id,
                execution_id=context.execution_id,
                started_at=context.started_at,
                error=e,
                error_message=str(e),
                error_type=type(e).__name__
            )
    
    async def _create_audit_entry(self, event, context: HandlerExecutionContext) -> dict[str, Any]:
        """Create audit log entry from event."""
        event_type = event.__class__.__name__
        
        # Base audit entry
        audit_entry = {
            "audit_id": str(uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": str(event.event_id),
            "event_type": event_type,
            "action": self._get_action_from_event_type(event_type),
            "correlation_id": context.correlation_id,
            "execution_id": str(context.execution_id),
            "source": "identity_service",
            "category": self._get_category_from_event_type(event_type),
        }
        
        # Extract common fields
        if hasattr(event, 'user_id') and event.user_id:
            audit_entry["user_id"] = str(event.user_id)
            audit_entry["subject_type"] = "user"
            audit_entry["subject_id"] = str(event.user_id)
        
        if hasattr(event, 'session_id') and event.session_id:
            audit_entry["session_id"] = str(event.session_id)
        
        if hasattr(event, 'ip_address') and event.ip_address:
            audit_entry["ip_address"] = event.ip_address
        
        if hasattr(event, 'user_agent') and event.user_agent:
            audit_entry["user_agent"] = event.user_agent
        
        # Add event-specific data
        audit_entry["event_data"] = self._extract_event_data(event)
        
        # Add risk and compliance information
        audit_entry["risk_level"] = self._assess_event_risk(event)
        audit_entry["compliance_relevant"] = self._is_compliance_relevant(event_type)
        
        return audit_entry
    
    def _get_action_from_event_type(self, event_type: str) -> str:
        """Map event type to audit action."""
        action_mapping = {
            # User lifecycle
            "UserCreated": "user.create",
            "UserActivated": "user.activate",
            "UserSuspended": "user.suspend",
            "UserDeactivated": "user.deactivate",
            "UserDeleted": "user.delete",
            
            # Authentication
            "LoginSuccessful": "auth.login.success",
            "LoginFailed": "auth.login.failed",
            "AccountLockedOut": "auth.account.locked",
            "AccountUnlocked": "auth.account.unlocked",
            
            # Password
            "PasswordChanged": "auth.password.changed",
            "PasswordResetRequested": "auth.password.reset_requested",
            
            # MFA
            "MFAEnabled": "auth.mfa.enabled",
            "MFADisabled": "auth.mfa.disabled",
            
            # Session
            "SessionCreated": "session.created",
            "SessionRevoked": "session.revoked",
            "TokenRefreshed": "token.refreshed",
            
            # Security
            "SecurityAlertRaised": "security.alert.raised",
            "SuspiciousActivityDetected": "security.suspicious_activity",
            "IPBlocklisted": "security.ip.blocklisted",
            "IPAllowlisted": "security.ip.allowlisted",
            "ComplianceViolationDetected": "compliance.violation",
        }
        
        return action_mapping.get(event_type, f"event.{event_type.lower()}")
    
    def _get_category_from_event_type(self, event_type: str) -> str:
        """Map event type to audit category."""
        if event_type.startswith(("User", "Profile")):
            return "user_management"
        if event_type.startswith(("Login", "Auth", "Password", "MFA", "Account")):
            return "authentication"
        if event_type.startswith(("Session", "Token")):
            return "session_management"
        if event_type.startswith(("Security", "Suspicious", "IP")):
            return "security"
        if event_type.startswith("Compliance"):
            return "compliance"
        return "general"
    
    def _extract_event_data(self, event) -> dict[str, Any]:
        """Extract relevant data from event for audit."""
        # Get all attributes except metadata and event_id
        event_data = {}
        
        for attr in dir(event):
            if not attr.startswith('_') and attr not in ['metadata', 'event_id', 'occurred_at']:
                try:
                    value = getattr(event, attr)
                    if not callable(value):
                        # Convert UUIDs to strings
                        if hasattr(value, '__str__') and 'UUID' in str(type(value)):
                            event_data[attr] = str(value)
                        elif isinstance(value, datetime):
                            event_data[attr] = value.isoformat()
                        elif isinstance(value, str | int | float | bool | list | dict | type(None)):
                            event_data[attr] = value
                        else:
                            event_data[attr] = str(value)
                except Exception:
                    # Skip attributes that can't be accessed
                    logger.debug(f"Skipped attribute {attr} during event data extraction")
        
        return event_data
    
    def _assess_event_risk(self, event) -> str:
        """Assess risk level of event for audit purposes."""
        event_type = event.__class__.__name__
        
        high_risk_events = {
            "UserDeleted", "UserSuspended", "AccountLockedOut",
            "SecurityAlertRaised", "SuspiciousActivityDetected",
            "ComplianceViolationDetected", "IPBlocklisted"
        }
        
        medium_risk_events = {
            "PasswordChanged", "MFADisabled", "SessionRevoked",
            "LoginFailed", "UserDeactivated"
        }
        
        if event_type in high_risk_events:
            return "high"
        if event_type in medium_risk_events:
            return "medium"
        return "low"
    
    def _is_compliance_relevant(self, event_type: str) -> bool:
        """Check if event is relevant for compliance."""
        compliance_events = {
            "UserCreated", "UserDeleted", "UserSuspended", "UserDeactivated",
            "LoginSuccessful", "LoginFailed", "PasswordChanged",
            "MFAEnabled", "MFADisabled", "SecurityAlertRaised",
            "ComplianceViolationDetected", "IPBlocklisted"
        }
        
        return event_type in compliance_events
    
    async def _store_audit_entry(self, audit_entry: dict[str, Any]) -> str:
        """Store audit entry in audit database."""
        # TODO: Integrate with audit database
        await asyncio.sleep(0.05)  # Simulate database write
        
        audit_id = audit_entry["audit_id"]
        
        logger.debug(f"Audit entry stored with ID {audit_id}")
        
        return audit_id
    
    async def _index_audit_entry(self, audit_entry: dict[str, Any], audit_id: str) -> None:
        """Index audit entry for search."""
        # TODO: Integrate with search indexing service
        await asyncio.sleep(0.02)  # Simulate indexing
        
        logger.debug(f"Audit entry {audit_id} indexed for search")
    
    async def _update_compliance_metrics(self, event_type: str, audit_entry: dict[str, Any]) -> None:
        """Update compliance metrics."""
        # TODO: Integrate with compliance metrics service
        await asyncio.sleep(0.01)  # Simulate metrics update
        
        logger.debug(f"Compliance metrics updated for {event_type}")
    
    async def _apply_retention_policies(self, event_type: str) -> None:
        """Apply audit log retention policies."""
        # TODO: Integrate with data retention service
        await asyncio.sleep(0.01)  # Simulate retention check
        
        logger.debug(f"Retention policies applied for {event_type}")


# Export all handlers
__all__ = [
    "AuditLogHandler",
    "SecurityEventHandler",
]