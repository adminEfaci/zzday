"""
MFA Enabled Event Handler

Handles MFA enablement events from the Identity module and creates 
corresponding audit trails with security and compliance categorization.
"""

import logging
from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from app.modules.identity.domain.entities.user.user_events import MFAEnabled
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.domain.enums import AuditAction, AuditOutcome, AuditSeverity, AuditCategory
from app.core.events.handlers import EventHandler
from app.core.logging import get_logger


logger = get_logger(__name__)


class MFAEnabledEventHandler(EventHandler[MFAEnabled]):
    """Event handler for MFA enablement events."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: MFAEnabled) -> None:
        """Handle MFA enabled event by creating audit trails.
        
        Args:
            event: MFA enabled event from Identity module
        """
        try:
            logger.info(
                "Processing MFA enabled event",
                user_id=str(event.user_id),
                device_id=str(event.device_id),
                device_type=event.device_type,
                event_id=str(event.event_id)
            )
            
            # Create primary audit trail for MFA enablement
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.SECURITY_SETTING_CHANGED,
                operation="mfa.enable",
                description=f"MFA enabled with {event.device_type} device '{event.device_name}'",
                resource_type="user_security",
                resource_id=str(event.user_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.INFO,
                category=AuditCategory.SECURITY,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=getattr(event, 'ip_address', None),
                user_agent=getattr(event, 'user_agent', None),
                tags=["mfa", "security", "authentication", event.device_type],
                compliance_tags=["ISO27001", "NIST-800-63B", "security-controls"],
                custom_fields={
                    "device_id": str(event.device_id),
                    "device_type": event.device_type,
                    "device_name": event.device_name,
                    "backup_codes_generated": event.backup_codes_generated,
                    "enabled_at": event.enabled_at.isoformat() if event.enabled_at else None,
                    "security_improvement": "high",
                    "authentication_strength": "strong"
                }
            )
            
            # Create security-specific audit trail
            await self._create_security_audit_trail(event)
            
            # Create compliance audit trail if first MFA device
            if getattr(event, 'is_first_device', False):
                await self._create_compliance_audit_trail(event)
            
            logger.info(
                "Successfully processed MFA enabled event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process MFA enabled event",
                user_id=str(event.user_id),
                event_id=str(event.event_id),
                error=str(e)
            )
            # Don't re-raise to avoid disrupting the business process
    
    async def _create_security_audit_trail(self, event: MFAEnabled) -> None:
        """Create security-specific audit trail.
        
        Args:
            event: MFA enabled event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.SECURITY_CONTROL_ENABLED,
            operation="security.mfa_activated",
            description=f"Security control activated: {event.device_type} MFA",
            resource_type="security_control",
            resource_id=str(event.device_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.LOW,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["security-control", "mfa-activation", "risk-reduction"],
            compliance_tags=["security-best-practice", "authentication-enhancement"],
            custom_fields={
                "control_type": "multi_factor_authentication",
                "control_strength": self._get_control_strength(event.device_type),
                "risk_mitigation": "account_takeover_prevention",
                "compliance_requirement": self._is_compliance_required(event.user_id)
            }
        )
    
    async def _create_compliance_audit_trail(self, event: MFAEnabled) -> None:
        """Create compliance audit trail for first MFA device.
        
        Args:
            event: MFA enabled event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.COMPLIANCE_CHECK,
            operation="compliance.mfa_requirement_met",
            description="User meets MFA compliance requirement",
            resource_type="compliance_requirement",
            resource_id="mfa_policy",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            category=AuditCategory.COMPLIANCE,
            event_id=str(event.event_id),
            tags=["compliance", "mfa-requirement", "policy-adherence"],
            compliance_tags=["SOC2", "ISO27001", "HIPAA", "PCI-DSS"],
            custom_fields={
                "requirement": "multi_factor_authentication",
                "policy_version": "2.0",
                "compliance_date": datetime.now(UTC).isoformat(),
                "attestation_required": False
            }
        )
    
    def _get_control_strength(self, device_type: str) -> str:
        """Get security control strength based on device type.
        
        Args:
            device_type: Type of MFA device
            
        Returns:
            Control strength level
        """
        strength_map = {
            "authenticator_app": "strong",
            "hardware_key": "very_strong",
            "sms": "moderate",
            "email": "moderate",
            "biometric": "strong",
            "backup_codes": "weak"
        }
        return strength_map.get(device_type.lower(), "moderate")
    
    def _is_compliance_required(self, user_id: UUID) -> bool:
        """Check if MFA is required for compliance.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if MFA is required for compliance
        """
        # In a real implementation, this would check user roles,
        # data access levels, and compliance requirements
        # For now, we'll assume MFA is recommended for all users
        return True